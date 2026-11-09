using System.Globalization;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Domain;
using Qhub.Features.Api;
using Qhub.Features.Documents;
using Qhub.Features.Storage;
using Qhub.Security;

namespace Qhub.Features.Uploads;

/// <summary>A chunked upload to finish in the background (<c>nonblocking</c>).</summary>
public sealed record CompleteUpload(int OwnerId, string Uuid, string FileName, long Size, string? ContentType, UploadParameters Parameters);

/// <summary>
/// Chunked uploads. Chunks are files at <c>tmp/chunks/{owner}/{uuid}/{offset}</c>, private to their uploader (RULE-040);
/// completion needs chunks covering exactly <c>[0, filesize)</c> (RULE-115 corrected).
/// </summary>
public sealed partial class Chunks(IOptions<QhubOptions> options, Documents.Documents docs, ContentStore store, ClientThrottle throttle,
    UploadStatusHub status, Channel<CompleteUpload> queue)
{
    readonly QhubOptions settings = options.Value;

    long MaxBytes => settings.MaxFileSizeMb * 1024L * 1024L;
    /// <summary>A chunk smaller than this must be the last one (legacy: 5 MB, or 1 MB when chunks are under 5 MB).</summary>
    long MinChunk => (settings.ChunkSizeMb < 5 ? 1 : 5) * 1024L * 1024L;

    public static string Root(QhubOptions o) => Path.Combine(Path.GetFullPath(o.DataDir), "tmp", "chunks");
    string Dir(int ownerId, string uuid) => Path.Combine(Root(settings), ownerId.ToString(CultureInfo.InvariantCulture), uuid);

    [GeneratedRegex("^[A-Za-z0-9-]{1,64}$")]
    private static partial Regex UuidFormat();

    /// <returns>Null on success, otherwise the error to answer.</returns>
    public async Task<IResult?> AddAsync(HttpContext http, int ownerId, string? uuid, long? offset, long? totalSize, IFormFile? file, CancellationToken ct)
    {
        if (uuid is null || !UuidFormat().IsMatch(uuid)) return ApiError.BadInput("invalid chunk id", ApiError.InvalidUserInput);
        if (offset is not >= 0 || totalSize is not > 0) return ApiError.BadInput("offset and filesize must be valid numbers", ApiError.InvalidUserInput);
        if (file is null) return ApiError.BadInput("http: no such file", ApiError.InvalidUserInput);
        if (totalSize > MaxBytes || offset > MaxBytes) return ApiError.BadInput("upload limit exceeded", ApiError.FileTooLarge);
        if (offset + file.Length > totalSize) return ApiError.BadInput("chunk exceeds the file size", ApiError.InvalidUserInput);
        if (file.Length < MinChunk && offset + file.Length < totalSize) return ApiError.BadInput("chunk is too small", ApiError.ChunkTooSmall);

        var dir = Dir(ownerId, uuid);
        if (!Directory.Exists(dir))
        {
            if (!await throttle.WaitAsync(ThrottleKind.NewUpload, http)) return Results.StatusCode(StatusCodes.Status429TooManyRequests);
            Directory.CreateDirectory(dir);
        }
        var path = Path.Combine(dir, offset.Value.ToString("D19", CultureInfo.InvariantCulture));
        await using var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1, FileOptions.Asynchronous);
        await file.CopyToAsync(output, ct);
        return null;
    }

    /// <summary>Completes now and answers with the file, or queues it and answers OK at once (<c>nonblocking</c>).</summary>
    public async Task<IResult> CompleteAsync(User owner, string uuid, string fileName, long size, string? contentType, UploadParameters parameters,
        bool nonBlocking, CancellationToken ct)
    {
        var job = new CompleteUpload(owner.Id, uuid, fileName, size, contentType, parameters);
        if (nonBlocking)
        {
            status.SetStatus(owner.Id, uuid, UploadStatus.Processing);
            await queue.Writer.WriteAsync(job, ct);
            return ApiError.Json(new { result = "OK" });
        }
        var (link, error) = await RunAsync(job, ct);
        if (link is null) return ApiError.BadInput(error!);
        var output = FileApiOutput.From(link, await docs.ContentOfAsync(link, ct), settings.PublicUrl);
        return ApiError.Json(output.AsResult());
    }

    /// <summary>Joins the chunks and creates the link. The chunks are removed either way.</summary>
    public async Task<(Link? Link, string? Error)> RunAsync(CompleteUpload job, CancellationToken ct)
    {
        var dir = UuidFormat().IsMatch(job.Uuid) ? Dir(job.OwnerId, job.Uuid) : null;
        if (dir is null || !Directory.Exists(dir)) return Fail("chunk file does not exist");
        var temp = store.NewTempFile();
        try
        {
            if (job.Size > MaxBytes) return Fail("upload limit exceeded");
            var parts = Directory.GetFiles(dir)
                .Select(p => (Path: p, Offset: long.Parse(Path.GetFileName(p), CultureInfo.InvariantCulture), Length: new FileInfo(p).Length))
                .OrderBy(p => p.Offset).ToList();
            long covered = 0;
            foreach (var part in parts)
            {
                if (part.Offset != covered) return Fail($"upload incomplete: bytes from offset {covered} are missing");
                covered += part.Length;
            }
            if (covered != job.Size) return Fail($"upload incomplete: {covered} of {job.Size} bytes received");

            status.SetStatus(job.OwnerId, job.Uuid, UploadStatus.Saving);
            using var hmac = docs.DedupHash(job.OwnerId);
            await using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1, FileOptions.Asynchronous))
            {
                var buffer = new byte[81920];
                foreach (var part in parts)
                {
                    await using var input = new FileStream(part.Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.Asynchronous);
                    int read;
                    while ((read = await input.ReadAsync(buffer, ct)) > 0)
                    {
                        hmac.AppendData(buffer, 0, read);
                        await output.WriteAsync(buffer.AsMemory(0, read), ct);
                    }
                }
            }
            var link = await docs.CreateAsync(job.OwnerId, temp, job.Size, hmac.GetHashAndReset(), job.FileName, job.ContentType ?? "", job.Parameters, null, ct);
            status.SetStatus(job.OwnerId, job.Uuid, UploadStatus.Finished, link.Id);
            return (link, null);
        }
        finally
        {
            File.Delete(temp);
            Directory.Delete(dir, recursive: true);
        }

        (Link?, string?) Fail(string message)
        {
            status.SetStatus(job.OwnerId, job.Uuid, UploadStatus.Error, error: message);
            return (null, message);
        }
    }
}

/// <summary>Finishes queued <c>nonblocking</c> chunked uploads.</summary>
public sealed class UploadCompletionWorker(Channel<CompleteUpload> queue, IServiceScopeFactory scopes, UploadStatusHub status,
    ILogger<UploadCompletionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var job in queue.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                using var scope = scopes.CreateScope();
                await scope.ServiceProvider.GetRequiredService<Chunks>().RunAsync(job, stoppingToken);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogError(e, "Completing chunked upload {Uuid} failed", job.Uuid);
                status.SetStatus(job.OwnerId, job.Uuid, UploadStatus.Error, error: "Server Error");
            }
        }
    }
}
