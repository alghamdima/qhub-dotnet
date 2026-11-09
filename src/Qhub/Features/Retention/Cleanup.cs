using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Audit;
using Qhub.Features.Storage;
using Qhub.Features.Uploads;

namespace Qhub.Features.Retention;

/// <summary>The clean-up pass (RULE-009, RULE-105, RULE-110, RULE-111).</summary>
public sealed class Cleanup(QhubDbContext db, Documents.Documents docs, ContentStore store, TimeProvider time, IOptions<QhubOptions> options,
    ILogger<Cleanup> logger)
{
    static readonly TimeSpan TempAge = TimeSpan.FromHours(24);
    /// <summary>A blob younger than this may belong to an upload whose row is not saved yet.</summary>
    static readonly TimeSpan OrphanAge = TimeSpan.FromHours(1);

    /// <summary>Links a clean-up deletes: past ExpireAt, no downloads left, due pending deletions, unfilled reservations (RULE-105).</summary>
    public IQueryable<Link> Candidates(DateTimeOffset now) => db.Links.Where(l =>
        (l.State == LinkState.Live && ((l.ExpireAt != null && l.ExpireAt < now) || l.DownloadsRemaining <= 0))
        || (l.State == LinkState.PendingDeletion && l.DeleteAt <= now)
        || (l.State == LinkState.Reserved && l.ReservedUntil < now));

    public async Task RunAsync(bool scheduled, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        foreach (var link in await Candidates(now).AsNoTracking().Select(l => new { l.Id, l.FileName, l.State }).ToListAsync(ct))
        {
            if (link.State == LinkState.PendingDeletion) db.Audit(now, null, "Deleted", link.Id, $"{link.FileName}, ID {link.Id}, deleted by the scheduled deletion");
            await db.SaveChangesAsync(ct);
            await docs.DeleteLinkNowAsync(link.Id, ct);
        }

        // Content no link uses: shared content stays until its last link is gone (RULE-009, RULE-111).
        foreach (var contentId in await db.StoredContents.Where(c => !db.Links.Any(l => l.ContentId == c.Id)).Select(c => c.Id).ToListAsync(ct))
            await docs.DeleteContentIfUnusedAsync(contentId, ct);

        await SweepOrphanBlobsAsync(now, ct);
        SweepTemp(now);

        await db.ApiKeys.Where(k => k.ExpiresAt != null && k.ExpiresAt < now).ExecuteDeleteAsync(ct);
        await db.DownloadGrants.Where(g => g.ExpiresAt < now).ExecuteDeleteAsync(ct);
        await db.CountedPasses.Where(p => p.CountedAt < now.AddDays(-1)).ExecuteDeleteAsync(ct);
        if (scheduled && options.Value.LogRetentionDays > 0)
            await db.AuditEntries.Where(a => a.At < now.AddDays(-options.Value.LogRetentionDays)).ExecuteDeleteAsync(ct);
    }

    /// <summary>Blobs without a row: left behind when a blob delete failed (RULE-111 retry) or an upload crashed.</summary>
    async Task SweepOrphanBlobsAsync(DateTimeOffset now, CancellationToken ct)
    {
        var known = (await db.StoredContents.AsNoTracking().Select(c => c.Location).ToListAsync(ct)).ToHashSet(StringComparer.Ordinal);
        await foreach (var (location, modified) in store.ListAsync(ct))
        {
            if (known.Contains(location) || now - modified < OrphanAge) continue;
            try { await store.DeleteAsync(new StoredContent { Location = location, StoreKind = store.CurrentKind }, ct); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or Amazon.Runtime.AmazonServiceException)
            {
                logger.LogWarning(e, "Deleting orphan blob {Location} failed; retrying next run", location);
            }
        }
    }

    void SweepTemp(DateTimeOffset now)
    {
        var tmp = Path.Combine(Path.GetFullPath(options.Value.DataDir), "tmp");
        if (!Directory.Exists(tmp)) return;
        var cutoff = (now - TempAge).UtcDateTime;
        foreach (var file in Directory.EnumerateFiles(tmp))
            if (File.GetLastWriteTimeUtc(file) < cutoff) TryDelete(() => File.Delete(file));
        var chunks = Chunks.Root(options.Value);
        if (!Directory.Exists(chunks)) return;
        foreach (var upload in Directory.EnumerateDirectories(chunks).SelectMany(Directory.EnumerateDirectories))
            if (Directory.GetLastWriteTimeUtc(upload) < cutoff) TryDelete(() => Directory.Delete(upload, recursive: true));
    }

    void TryDelete(Action delete)
    {
        try { delete(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { logger.LogWarning(e, "Removing a stale temp file failed"); }
    }
}

/// <summary>Runs the clean-up at start, then one hour after each run ends (RULE-110).</summary>
public sealed class CleanupWorker(IServiceScopeFactory scopes, TimeProvider time, ILogger<CleanupWorker> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        for (var scheduled = false; !stoppingToken.IsCancellationRequested; scheduled = true)
        {
            try
            {
                using var scope = scopes.CreateScope();
                await scope.ServiceProvider.GetRequiredService<Cleanup>().RunAsync(scheduled, stoppingToken);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogError(e, "Clean-up failed; retrying in an hour");
            }
            await Task.Delay(Interval, time, stoppingToken);
        }
    }
}
