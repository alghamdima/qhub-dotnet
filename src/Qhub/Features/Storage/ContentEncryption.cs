using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;

namespace Qhub.Features.Storage;

/// <summary>
/// Encryption at rest, "none" or "on" (brief Q4). Each content gets a random data key, wrapped by a master key derived from
/// <c>QHUB_ENCRYPTION_PASSWORD</c>; the <see cref="KeyCheck"/> row lets startup verify the password and the mode (RULE-002, 003, 039).
/// </summary>
public sealed class ContentEncryption
{
    public const int SegmentSize = 64 * 1024;
    const int TagSize = 16, NonceSize = 12, KeySize = 32, Iterations = 600_000;

    byte[]? masterKey;

    public bool IsOn => masterKey is not null;

    /// <summary>Checks the mode and password against the stored <see cref="KeyCheck"/>; throws to stop startup.</summary>
    public async Task InitializeAsync(QhubDbContext db, QhubOptions options, CancellationToken ct)
    {
        var on = options.Encryption.Equals("on", StringComparison.OrdinalIgnoreCase);
        var check = await db.KeyChecks.SingleOrDefaultAsync(ct);
        if (!on)
        {
            if (await db.StoredContents.AnyAsync(c => c.Encrypted, ct))
                throw new InvalidOperationException("QHUB_ENCRYPTION is \"none\" but encrypted content exists. Set it back to \"on\", or delete the encrypted files first.");
            return;
        }

        if (check is null || check.Mode != "on")
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var key = Derive(options.EncryptionPassword, salt);
            if (check is null) db.KeyChecks.Add(new KeyCheck { Salt = salt, Verifier = Verifier(key), Mode = "on" });
            else (check.Salt, check.Verifier, check.Mode) = (salt, Verifier(key), "on");
            await db.SaveChangesAsync(ct);
            masterKey = key;
            return;
        }

        var derived = Derive(options.EncryptionPassword, check.Salt);
        if (!CryptographicOperations.FixedTimeEquals(Verifier(derived), check.Verifier))
            throw new InvalidOperationException("QHUB_ENCRYPTION_PASSWORD is not the password Qhub was set up with.");
        masterKey = derived;
    }

    static byte[] Derive(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, KeySize);

    static byte[] Verifier(byte[] key) => HMACSHA256.HashData(key, "qhub-key-check"u8);

    /// <summary>A new data key and its wrapped form (nonce + ciphertext + tag) for <see cref="StoredContent.WrappedKey"/>.</summary>
    public (byte[] Key, byte[] Wrapped) NewDataKey()
    {
        var key = RandomNumberGenerator.GetBytes(KeySize);
        var wrapped = new byte[NonceSize + KeySize + TagSize];
        RandomNumberGenerator.Fill(wrapped.AsSpan(0, NonceSize));
        using var aes = new AesGcm(masterKey ?? throw new InvalidOperationException("Encryption is off."), TagSize);
        aes.Encrypt(wrapped.AsSpan(0, NonceSize), key, wrapped.AsSpan(NonceSize, KeySize), wrapped.AsSpan(NonceSize + KeySize));
        return (key, wrapped);
    }

    public byte[] Unwrap(byte[] wrapped)
    {
        var key = new byte[KeySize];
        using var aes = new AesGcm(masterKey ?? throw new InvalidOperationException("QHUB_ENCRYPTION is off but this content is encrypted."), TagSize);
        aes.Decrypt(wrapped.AsSpan(0, NonceSize), wrapped.AsSpan(NonceSize, KeySize), wrapped.AsSpan(NonceSize + KeySize), key);
        return key;
    }

    /// <summary>Encrypts <paramref name="input"/> in 64 KiB segments; each segment's index and a final flag are authenticated.</summary>
    public static async Task EncryptAsync(Stream input, Stream output, byte[] key, CancellationToken ct)
    {
        using var aes = new AesGcm(key, TagSize);
        var plain = new byte[SegmentSize];
        var cipher = new byte[SegmentSize + TagSize];
        var next = new byte[SegmentSize];
        var length = await ReadFullAsync(input, plain, ct);
        for (long index = 0; ; index++)
        {
            var nextLength = length == SegmentSize ? await ReadFullAsync(input, next, ct) : 0;
            var final = nextLength == 0;
            Seal(aes, index, final, plain.AsSpan(0, length), cipher);
            await output.WriteAsync(cipher.AsMemory(0, length + TagSize), ct);
            if (final) return;
            (plain, next, length) = (next, plain, nextLength);
        }
    }

    static void Seal(AesGcm aes, long index, bool final, ReadOnlySpan<byte> plain, Span<byte> cipher)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> aad = stackalloc byte[9];
        Frame(index, final, nonce, aad);
        aes.Encrypt(nonce, plain, cipher[..plain.Length], cipher.Slice(plain.Length, TagSize), aad);
    }

    static void Frame(long index, bool final, Span<byte> nonce, Span<byte> aad)
    {
        nonce.Clear();
        BinaryPrimitives.WriteInt64BigEndian(nonce[4..], index);
        BinaryPrimitives.WriteInt64BigEndian(aad, index);
        aad[8] = final ? (byte)1 : (byte)0;
    }

    static async Task<int> ReadFullAsync(Stream input, byte[] buffer, CancellationToken ct)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await input.ReadAsync(buffer.AsMemory(total), ct);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    /// <summary>The ciphertext length for <paramref name="plainLength"/> bytes.</summary>
    public static long CipherLength(long plainLength) => plainLength + Math.Max(1, (plainLength + SegmentSize - 1) / SegmentSize) * TagSize;

    /// <summary>A seekable plaintext view over the ciphertext, so Range requests work on encrypted content.</summary>
    public sealed class DecryptingStream(Stream cipher, byte[] key, long plainLength) : Stream
    {
        readonly AesGcm aes = new(key, TagSize);
        readonly byte[] segment = new byte[SegmentSize];
        readonly byte[] sealedSegment = new byte[SegmentSize + TagSize];
        long cachedIndex = -1;
        int cachedLength;
        long position;
        long Segments => Math.Max(1, (plainLength + SegmentSize - 1) / SegmentSize);

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => plainLength;
        public override long Position { get => position; set => position = Math.Clamp(value, 0, plainLength); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (position >= plainLength || buffer.IsEmpty) return 0;
            var index = position / SegmentSize;
            Load(index);
            var within = (int)(position - index * SegmentSize);
            var n = Math.Min(buffer.Length, cachedLength - within);
            segment.AsSpan(within, n).CopyTo(buffer);
            position += n;
            return n;
        }

        void Load(long index)
        {
            if (index == cachedIndex) return;
            var final = index == Segments - 1;
            var length = final ? (int)(plainLength - index * SegmentSize) : SegmentSize;
            cipher.Position = index * (SegmentSize + TagSize);
            cipher.ReadExactly(sealedSegment, 0, length + TagSize);
            Span<byte> nonce = stackalloc byte[NonceSize];
            Span<byte> aad = stackalloc byte[9];
            Frame(index, final, nonce, aad);
            aes.Decrypt(nonce, sealedSegment.AsSpan(0, length), sealedSegment.AsSpan(length, TagSize), segment.AsSpan(0, length), aad);
            (cachedIndex, cachedLength) = (index, length);
        }

        public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => position + offset,
            _ => plainLength + offset,
        };

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                aes.Dispose();
                cipher.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
