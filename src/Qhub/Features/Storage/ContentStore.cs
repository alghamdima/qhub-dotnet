using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Domain;

namespace Qhub.Features.Storage;

/// <summary>How to deliver content: a seekable stream (Range support), or a short-lived S3 URL to redirect to.</summary>
public sealed record ContentSource(Stream? Stream, string? RedirectUrl);

/// <summary>
/// Blobs on the local data volume (optionally encrypted, RULE-145) or in S3 (bucket-side encryption, brief Q4).
/// The store used for new content follows <c>QHUB_AWS_BUCKET</c>; existing content is read from wherever it was stored.
/// </summary>
public sealed class ContentStore(IOptions<QhubOptions> options, ContentEncryption encryption) : IDisposable
{
    readonly QhubOptions settings = options.Value;
    readonly Lazy<AmazonS3Client> s3 = new(() => CreateS3(options.Value));

    string Root => Path.GetFullPath(settings.DataDir);
    bool UseS3 => settings.AwsBucket.Length > 0;

    /// <summary>A new temporary file under the data volume, for an upload being received.</summary>
    public string NewTempFile()
    {
        var dir = Path.Combine(Root, "tmp");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, Guid.NewGuid().ToString("N"));
    }

    /// <summary>Moves a received upload into the store and returns its (unsaved) <see cref="StoredContent"/>.</summary>
    public async Task<StoredContent> SaveAsync(string tempFile, long size, byte[]? dedupKey, CancellationToken ct)
    {
        var content = new StoredContent { Id = Guid.NewGuid(), Location = "", SizeBytes = size, DedupKey = dedupKey };
        if (UseS3)
        {
            content.StoreKind = StoreKind.S3;
            content.Location = content.Id.ToString("N");
            await s3.Value.PutObjectAsync(new PutObjectRequest { BucketName = settings.AwsBucket, Key = content.Location, FilePath = tempFile }, ct);
            File.Delete(tempFile);
            return content;
        }

        content.StoreKind = StoreKind.Local;
        content.Location = Path.Combine("content", content.Id.ToString("N"));
        var target = Path.Combine(Root, content.Location);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        if (encryption.IsOn)
        {
            var (key, wrapped) = encryption.NewDataKey();
            await using (var input = File.OpenRead(tempFile))
            await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.Asynchronous))
                await ContentEncryption.EncryptAsync(input, output, key, ct);
            File.Delete(tempFile);
            (content.Encrypted, content.WrappedKey) = (true, wrapped);
        }
        else
        {
            File.Move(tempFile, target);
        }
        return content;
    }

    /// <summary>Opens content for a download. Null when the blob is missing.</summary>
    public async Task<ContentSource?> OpenAsync(StoredContent content, string fileName, bool redirectAllowed, CancellationToken ct)
    {
        if (content.StoreKind == StoreKind.S3)
        {
            if (redirectAllowed && !settings.AwsProxyDownload)
            {
                var url = await s3.Value.GetPreSignedURLAsync(new GetPreSignedUrlRequest
                {
                    BucketName = settings.AwsBucket,
                    Key = content.Location,
                    Expires = DateTime.UtcNow.AddMinutes(1),
                    ResponseHeaderOverrides = { ContentDisposition = $"attachment; filename*=UTF-8''{Uri.EscapeDataString(fileName)}" },
                });
                return new ContentSource(null, url);
            }
            try
            {
                var response = await s3.Value.GetObjectAsync(settings.AwsBucket, content.Location, ct);
                return new ContentSource(response.ResponseStream, null);
            }
            catch (AmazonS3Exception e) when (e.StatusCode == System.Net.HttpStatusCode.NotFound) { return null; }
        }

        var path = LocalPath(content);
        if (path is null || !File.Exists(path)) return null;
        Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1, FileOptions.Asynchronous);
        if (content.Encrypted)
            stream = new ContentEncryption.DecryptingStream(stream, encryption.Unwrap(content.WrappedKey!), content.SizeBytes);
        return new ContentSource(stream, null);
    }

    /// <summary>Deletes the blob; a missing blob is not an error.</summary>
    public async Task DeleteAsync(StoredContent content, CancellationToken ct)
    {
        if (content.StoreKind == StoreKind.S3)
            await s3.Value.DeleteObjectAsync(settings.AwsBucket, content.Location, ct);
        else if (LocalPath(content) is { } path)
            File.Delete(path);
    }

    /// <summary>Whether a blob still exists (dedup reuses only content that is really there).</summary>
    public async Task<bool> ExistsAsync(StoredContent content, CancellationToken ct)
    {
        if (content.StoreKind != StoreKind.S3) return LocalPath(content) is { } path && File.Exists(path);
        try
        {
            await s3.Value.GetObjectMetadataAsync(settings.AwsBucket, content.Location, ct);
            return true;
        }
        catch (AmazonS3Exception e) when (e.StatusCode == System.Net.HttpStatusCode.NotFound) { return false; }
    }

    /// <summary>The store new content goes to.</summary>
    public StoreKind CurrentKind => UseS3 ? StoreKind.S3 : StoreKind.Local;

    /// <summary>Every blob in the current store, as the <see cref="StoredContent.Location"/> it would have.</summary>
    public async IAsyncEnumerable<(string Location, DateTimeOffset Modified)> ListAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        if (!UseS3)
        {
            var dir = Path.Combine(Root, "content");
            if (!Directory.Exists(dir)) yield break;
            foreach (var file in Directory.EnumerateFiles(dir))
                yield return (Path.Combine("content", Path.GetFileName(file)), File.GetLastWriteTimeUtc(file));
            yield break;
        }
        var request = new ListObjectsV2Request { BucketName = settings.AwsBucket };
        ListObjectsV2Response response;
        do
        {
            response = await s3.Value.ListObjectsV2Async(request, ct);
            foreach (var item in response.S3Objects ?? []) yield return (item.Key, item.LastModified ?? DateTime.UtcNow);
            request.ContinuationToken = response.NextContinuationToken;
        } while (response.IsTruncated == true);
    }

    string? LocalPath(StoredContent content)
    {
        var path = Path.GetFullPath(Path.Combine(Root, content.Location));
        return path.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.Ordinal) ? path : null;
    }

    static AmazonS3Client CreateS3(QhubOptions o)
    {
        var config = new AmazonS3Config { AuthenticationRegion = o.AwsRegion };
        if (o.AwsEndpoint.Length > 0) (config.ServiceURL, config.ForcePathStyle) = (o.AwsEndpoint, true);
        else config.RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(o.AwsRegion);
        return new AmazonS3Client(new BasicAWSCredentials(o.AwsKey, o.AwsKeySecret), config);
    }

    public void Dispose()
    {
        if (s3.IsValueCreated) s3.Value.Dispose();
    }
}
