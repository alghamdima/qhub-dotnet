using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Audit;
using Qhub.Features.Storage;
using Qhub.Features.Uploads;
using Qhub.Security;

namespace Qhub.Features.Documents;

public sealed class UploadTooLargeException() : Exception("The file is too large");

/// <summary>Links and their content: create, reserve and fill, edit, delete, restore, replace, duplicate.</summary>
public sealed partial class Documents(QhubDbContext db, ContentStore store, AccessCodes codes, TimeProvider time,
    IOptions<QhubOptions> options, ILogger<Documents> logger)
{
    readonly QhubOptions settings = options.Value;
    readonly byte[] serverKey = Convert.FromBase64String(options.Value.ServerKey);

    public static readonly TimeSpan ReservationTime = TimeSpan.FromHours(1);

    long MaxBytes => settings.MaxFileSizeMb * 1024L * 1024L;

    /// <summary>Receives an upload and creates its link, or fills <paramref name="reserved"/> (RULE-122).</summary>
    public async Task<Link> StoreAsync(int ownerId, Stream upload, string fileName, string contentType, UploadParameters parameters,
        Link? reserved, CancellationToken ct)
    {
        var temp = store.NewTempFile();
        try
        {
            var (size, dedupKey) = await SpoolAsync(upload, temp, ownerId, ct);
            return await CreateAsync(ownerId, temp, size, dedupKey, fileName, contentType, parameters, reserved, ct);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    /// <summary>Creates the link for a fully received file (also used by chunked uploads).</summary>
    public async Task<Link> CreateAsync(int ownerId, string tempFile, long size, byte[] dedupKey, string fileName, string contentType,
        UploadParameters parameters, Link? reserved, CancellationToken ct)
    {
        var content = await ContentForAsync(tempFile, size, dedupKey, ct);
        var now = time.GetUtcNow();
        var link = reserved ?? new Link { Id = LinkRules.NewId(settings.LengthId), OwnerId = ownerId };
        link.ContentId = content.Id;
        link.FileName = SanitiseFileName(fileName);
        link.ContentType = SanitiseContentType(contentType);
        link.AccessCodeMac = codes.Mac(parameters.Code);
        link.State = LinkState.Live;
        link.ReservedUntil = null;
        link.DownloadsRemaining = parameters.Downloads;
        link.ExpireAt = parameters.ExpireAt;
        link.UploadedAt = now;
        if (reserved is null) db.Links.Add(link);
        db.Audit(now, ownerId, "Upload", link.Id, $"{link.FileName}, ID {link.Id}, uploaded");
        await db.SaveChangesAsync(ct);
        return link;
    }

    /// <summary>
    /// Identical content from the same owner is stored once and keeps its encryption key (RULE-008, RULE-006 corrected, brief Q3).
    /// </summary>
    async Task<StoredContent> ContentForAsync(string tempFile, long size, byte[] dedupKey, CancellationToken ct)
    {
        var existing = await db.StoredContents.FirstOrDefaultAsync(c => c.DedupKey == dedupKey, ct);
        if (existing is not null)
        {
            if (await store.ExistsAsync(existing, ct)) return existing;
            existing.DedupKey = null; // its blob is gone: free the key for the new copy
        }
        var content = await store.SaveAsync(tempFile, size, dedupKey, ct);
        db.StoredContents.Add(content);
        return content;
    }

    /// <summary>Copies the upload to <paramref name="temp"/>, enforcing the size limit, and computes the owner-scoped dedup key.</summary>
    public async Task<(long Size, byte[] DedupKey)> SpoolAsync(Stream upload, string temp, int ownerId, CancellationToken ct)
    {
        using var hmac = DedupHash(ownerId);
        var buffer = new byte[81920];
        long size = 0;
        await using var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1, FileOptions.Asynchronous);
        int read;
        while ((read = await upload.ReadAsync(buffer, ct)) > 0)
        {
            size += read;
            if (size > MaxBytes) throw new UploadTooLargeException();
            hmac.AppendData(buffer, 0, read);
            await file.WriteAsync(buffer.AsMemory(0, read), ct);
        }
        return (size, hmac.GetHashAndReset());
    }

    public IncrementalHash DedupHash(int ownerId)
    {
        var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, serverKey);
        hmac.AppendData(Encoding.UTF8.GetBytes($"qhub-dedup\n{ownerId}\n"));
        return hmac;
    }

    /// <summary>A link reserved before its document exists, so its QR code can be printed in the PDF (RULE-107).</summary>
    public async Task<Link> ReserveAsync(int ownerId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var link = new Link { Id = LinkRules.NewId(settings.LengthId), OwnerId = ownerId, State = LinkState.Reserved, ReservedUntil = now + ReservationTime };
        db.Links.Add(link);
        db.Audit(now, ownerId, "Reserve", link.Id, $"ID {link.Id} reserved");
        await db.SaveChangesAsync(ct);
        return link;
    }

    /// <summary>
    /// Edits a live link (RULE-120 corrected, RULE-046): 0 downloads or a 0 timestamp mean unlimited; a new code must be valid,
    /// revokes passes and lifts the lock (RULE-048 corrected, RULE-065, RULE-012).
    /// </summary>
    public async Task ModifyAsync(Link link, int actorId, int? downloads, long? expiryTimestamp, string? code, CancellationToken ct)
    {
        if (downloads is { } d) link.DownloadsRemaining = d == 0 ? null : d;
        if (expiryTimestamp is { } ts) link.ExpireAt = ts == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(ts);
        if (code is not null)
        {
            link.AccessCodeMac = codes.Mac(code);
            link.CodeStamp++;
            await db.CodeLocks.Where(c => c.LinkId == link.Id).ExecuteDeleteAsync(ct);
        }
        db.Audit(time.GetUtcNow(), actorId, "Edit", link.Id, $"{link.FileName}, ID {link.Id}, edited");
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Deletes now (RULE-112), or hides the link and deletes it after <paramref name="delay"/> (RULE-113).</summary>
    public async Task DeleteAsync(Link link, int actorId, TimeSpan delay, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        db.Audit(now, actorId, "Delete", link.Id, $"{link.FileName}, ID {link.Id}, deleted");
        if (delay > TimeSpan.Zero)
        {
            link.State = LinkState.PendingDeletion;
            link.DeleteAt = now + delay;
            await db.SaveChangesAsync(ct);
            return;
        }
        await db.SaveChangesAsync(ct);
        await DeleteLinkNowAsync(link.Id, ct);
    }

    /// <summary>Restore works only on a pending link within its delay (RULE-114 corrected).</summary>
    public async Task<bool> RestoreAsync(Link link, int actorId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        if (link.State != LinkState.PendingDeletion || link.DeleteAt <= now) return false;
        link.State = LinkState.Live;
        link.DeleteAt = null;
        db.Audit(now, actorId, "Restore", link.Id, $"{link.FileName}, ID {link.Id}, restored");
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>
    /// Gives <paramref name="target"/> the content of <paramref name="source"/>: the link and its code stay, issued passes are
    /// revoked, the lock is kept, and the old content is deleted when no other link uses it (RULE-106 corrected).
    /// </summary>
    public async Task ReplaceAsync(Link target, Link source, bool deleteSource, int actorId, CancellationToken ct)
    {
        var oldContent = target.ContentId;
        var oldName = target.FileName;
        target.ContentId = source.ContentId;
        target.FileName = source.FileName;
        target.ContentType = source.ContentType;
        target.CodeStamp++;
        db.Audit(time.GetUtcNow(), actorId, "Replace", target.Id, $"{oldName}, ID {target.Id} had content replaced with {source.FileName} (ID {source.Id})");
        await db.SaveChangesAsync(ct);
        if (deleteSource) await DeleteLinkNowAsync(source.Id, ct);
        if (oldContent is { } id && id != target.ContentId) await DeleteContentIfUnusedAsync(id, ct);
    }

    /// <summary>A new link to the same content. It keeps the original's code or takes a new valid one; never none (RULE-062 corrected).</summary>
    public async Task<Link> DuplicateAsync(Link source, int ownerId, int? downloads, int? expiryDays, string? newCode, string? fileName, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var copy = new Link
        {
            Id = LinkRules.NewId(settings.LengthId),
            OwnerId = ownerId,
            ContentId = source.ContentId,
            FileName = fileName is null ? source.FileName : SanitiseFileName(fileName),
            ContentType = source.ContentType,
            AccessCodeMac = newCode is null ? source.AccessCodeMac : codes.Mac(newCode),
            State = LinkState.Live,
            DownloadsRemaining = downloads is { } d ? (d == 0 ? null : d) : source.DownloadsRemaining,
            ExpireAt = expiryDays is { } days ? (days == 0 || days > UploadParameters.MaxExpiryDays ? null : now.AddDays(days)) : source.ExpireAt,
            UploadedAt = now,
        };
        db.Links.Add(copy);
        db.Audit(now, ownerId, "Duplicate", copy.Id, $"{copy.FileName}, ID {copy.Id}, copy of ID {source.Id}");
        await db.SaveChangesAsync(ct);
        return copy;
    }

    public Task<StoredContent?> ContentOfAsync(Link link, CancellationToken ct) =>
        link.ContentId is { } id ? db.StoredContents.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct) : Task.FromResult<StoredContent?>(null);

    /// <summary>Deletes a link row now and its content when no other link uses it.</summary>
    public async Task DeleteLinkNowAsync(string linkId, CancellationToken ct)
    {
        var contentId = await db.Links.Where(l => l.Id == linkId).Select(l => l.ContentId).FirstOrDefaultAsync(ct);
        await db.Links.Where(l => l.Id == linkId).ExecuteDeleteAsync(ct);
        if (contentId is { } id) await DeleteContentIfUnusedAsync(id, ct);
    }

    /// <summary>
    /// The row goes first, guarded by "no link uses it" in the same statement; the blob after. A failed blob delete leaves an
    /// orphan that the hourly sweep removes (RULE-111).
    /// </summary>
    public async Task DeleteContentIfUnusedAsync(Guid contentId, CancellationToken ct)
    {
        var content = await db.StoredContents.AsNoTracking().FirstOrDefaultAsync(c => c.Id == contentId, ct);
        if (content is null) return;
        var deleted = await db.StoredContents.Where(c => c.Id == contentId && !db.Links.Any(l => l.ContentId == contentId)).ExecuteDeleteAsync(ct);
        if (deleted == 0) return;
        try { await store.DeleteAsync(content, ct); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or Amazon.Runtime.AmazonServiceException)
        {
            logger.LogWarning(e, "Deleting the blob of content {ContentId} failed; the orphan sweep will retry", contentId);
        }
    }

    /// <summary>Control characters removed, at most 400 characters (legacy <c>SanitiseFilename</c>).</summary>
    public static string SanitiseFileName(string name)
    {
        var clean = new string(name.Where(c => !char.IsControl(c)).ToArray());
        return clean.Length > 400 ? clean[..400] + "..." : clean;
    }

    public static string SanitiseContentType(string? contentType) =>
        contentType is null || contentType.Length > 100 || contentType.Trim().Length < 2
            ? "application/octet-stream"
            : ContentTypeChars().Replace(contentType, "");

    [GeneratedRegex(@"[^a-zA-Z0-9!#$&^_.+\-/;= ]")]
    private static partial Regex ContentTypeChars();
}
