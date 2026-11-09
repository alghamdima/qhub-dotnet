using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Audit;
using Qhub.Features.Portal;
using Qhub.Features.Storage;
using Qhub.Features.Uploads;
using Qhub.Security;

namespace Qhub.Features.Delivery;

/// <summary>Customer download <c>/downloadFile</c> (spec §3.2; RULE-118, RULE-007 and RULE-109 corrected).</summary>
public static class DeliveryEndpoints
{
    public static void MapDelivery(this IEndpointRouteBuilder app) => app.MapGet("/downloadFile", DownloadAsync);

    static async Task<IResult> DownloadAsync(string? id, HttpContext http, QhubDbContext db, Passes passes, ContentStore store,
        ClientThrottle throttle, UploadStatusHub hub, IOptions<QhubOptions> options, TimeProvider time, CancellationToken ct)
    {
        http.Response.Headers.CacheControl = "no-store, no-cache";
        var now = time.GetUtcNow();
        // Not Servable(): a pass already counted may still resume after the last download brought the count to 0.
        var link = id is null ? null : await db.Links.AsNoTracking()
            .Where(l => l.Id == id && l.State == LinkState.Live && l.ContentId != null && (l.ExpireAt == null || l.ExpireAt >= now))
            .FirstOrDefaultAsync(ct);
        if (link is null) return await UnknownLinkAsync(http, throttle);

        if (passes.Validate(http.Request, link) is not { } passId)
            return Results.Redirect("./d?id=" + Uri.EscapeDataString(link.Id)); // nothing counted

        var content = await db.StoredContents.AsNoTracking().SingleAsync(c => c.Id == link.ContentId, ct);
        // Opened before counting: a missing blob counts nothing. The S3 redirect is counted too.
        var source = await store.OpenAsync(content, link.FileName, redirectAllowed: true, ct);
        var counted = source is null ? Count.Refused : await CountOnceAsync(db, link.Id, passId, now, ct);
        if (source is null) return await UnknownLinkAsync(http, throttle);
        if (counted == Count.Refused)
        {
            source?.Stream?.Dispose();
            return await UnknownLinkAsync(http, throttle);
        }
        if (counted == Count.First) await RecordAsync(db, hub, link, content, http, options.Value.SaveIp, now, ct);
        return source.RedirectUrl is { } url
            ? Results.Redirect(url)
            : Results.File(source.Stream!, link.ContentType, link.FileName, enableRangeProcessing: source.Stream!.CanSeek);
    }

    /// <summary>
    /// Counts the pass's download once, atomically, before the first byte (RULE-007/109 corrected). A pass already counted
    /// (a resume or a range read) is served without a new count. A first count needs a download left; never below 0.
    /// </summary>
    enum Count { Refused, First, AlreadyCounted }

    static async Task<Count> CountOnceAsync(QhubDbContext db, string linkId, string passId, DateTimeOffset now, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var first = await db.Database.ExecuteSqlAsync($"""
            INSERT INTO [CountedPasses] ([PassId], [LinkId], [CountedAt])
            SELECT {passId}, {linkId}, {now}
            WHERE NOT EXISTS (SELECT 1 FROM [CountedPasses] WITH (UPDLOCK, HOLDLOCK) WHERE [PassId] = {passId})
            """, ct) == 1;
        if (first)
        {
            var counted = await db.Links
                .Where(l => l.Id == linkId && l.State == LinkState.Live
                    && (l.ExpireAt == null || l.ExpireAt >= now)
                    && (l.DownloadsRemaining == null || l.DownloadsRemaining > 0))
                .ExecuteUpdateAsync(s => s
                    .SetProperty(l => l.DownloadsRemaining, l => l.DownloadsRemaining - 1)
                    .SetProperty(l => l.DownloadCount, l => l.DownloadCount + 1), ct);
            if (counted == 0) return Count.Refused; // disposing the transaction rolls back the pass row
        }
        await tx.CommitAsync(ct);
        return first ? Count.First : Count.AlreadyCounted;
    }

    /// <summary>A counted download: the log line, the traffic statistic, and the live count on the owner's admin page.</summary>
    static async Task RecordAsync(QhubDbContext db, UploadStatusHub hub, Link link, StoredContent content, HttpContext http, bool saveIp, DateTimeOffset now, CancellationToken ct)
    {
        var agent = new string(http.Request.Headers.UserAgent.ToString().Where(c => !char.IsControl(c)).Take(200).ToArray());
        var ip = saveIp ? $"IP {http.Connection.RemoteIpAddress}, " : "";
        db.Audit(now, null, "Download", link.Id, $"{link.FileName}, {ip}ID {link.Id}, Useragent {agent}", saveIp ? http.Connection.RemoteIpAddress?.ToString() : null);
        await db.SaveChangesAsync(ct);
        await ServerStats.RecordDownloadAsync(db, now, content.SizeBytes, ct);
        var after = await db.Links.AsNoTracking().Where(l => l.Id == link.Id).Select(l => new { l.DownloadCount, l.DownloadsRemaining }).FirstOrDefaultAsync(ct);
        if (after is not null) hub.Downloaded(link.OwnerId, link.Id, after.DownloadCount, after.DownloadsRemaining);
    }

    /// <summary>Unknown, expired or used-up links: the per-IP throttle (RULE-042), then the error page.</summary>
    internal static async Task<IResult> UnknownLinkAsync(HttpContext http, ClientThrottle throttle) =>
        await throttle.WaitAsync(ThrottleKind.UnknownLink, http)
            ? Results.Redirect("./error")
            : Results.StatusCode(StatusCodes.Status429TooManyRequests);
}
