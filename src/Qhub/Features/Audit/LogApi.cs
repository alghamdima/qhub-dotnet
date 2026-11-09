using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Api;

namespace Qhub.Features.Audit;

/// <summary><c>/api/logs/*</c>: the audit log as the legacy text lines the logs page filters, and the system status.</summary>
public static partial class LogApi
{
    public static void MapLogApi(this RouteGroupBuilder api)
    {
        api.MapGet("/logs/get", GetAsync).Requires(ApiPermissions.ManageLogs);
        api.MapDelete("/logs/delete", DeleteAsync).Requires(ApiPermissions.ManageLogs, adminOnly: true);
        api.MapGet("/logs/systemStatus", async (QhubDbContext db, ServerStats stats, TimeProvider time, CancellationToken ct) =>
            ApiError.Json(await stats.SnapshotAsync(db, time.GetUtcNow(), ct))).Requires(ApiPermissions.ManageLogs);
        api.MapDelete("/logs/resetTraffic", async (QhubDbContext db, CancellationToken ct) =>
        {
            await db.TrafficStats.ExecuteDeleteAsync(ct);
            return ApiError.Json(new { Result = "OK" });
        }).Requires(ApiPermissions.ManageLogs, adminOnly: true);
    }

    static string Category(string action) => action switch
    {
        "Upload" or "Reserve" or "Duplicate" => "upload",
        "Edit" or "Replace" or "Delete" or "Restore" or "ChangeOwner" or "Deleted" => "edit",
        "Download" => "download",
        "LogsDeleted" => "warning",
        "Startup" => "info",
        _ => "auth",
    };

    [GeneratedRegex(@"(\bID |Wrong password for file )[A-Za-z0-9]+")]
    private static partial Regex LinkIds();

    /// <summary>
    /// <c>date   [category] text by name (user #n)</c>, oldest first. Link IDs are hidden from readers without PERM_LIST (RULE-013).
    /// </summary>
    public static async Task<string> RenderAsync(QhubDbContext db, DateTimeOffset? since, bool showLinkIds, CancellationToken ct)
    {
        var entries = db.AuditEntries.AsNoTracking();
        if (since is { } s) entries = entries.Where(e => e.At > s);
        var rows = await entries.OrderBy(e => e.At).ThenBy(e => e.Id)
            .GroupJoin(db.Users, e => e.ActorUserId, u => u.Id, (e, users) => new { e, users })
            .SelectMany(x => x.users.DefaultIfEmpty(), (x, u) => new { x.e.At, x.e.Action, x.e.Detail, x.e.ActorUserId, Name = u == null ? null : u.Name })
            .ToListAsync(ct);
        var text = new StringBuilder();
        foreach (var row in rows)
        {
            text.Append(row.At.UtcDateTime.ToString("ddd, dd MMM yyyy HH:mm:ss 'UTC'", CultureInfo.InvariantCulture))
                .Append("   [").Append(Category(row.Action)).Append("] ").Append(row.Detail);
            if (row.ActorUserId is { } id && row.Action is not ("Login" or "PasswordChanged"))
                text.Append(" by ").Append(row.Name).Append(" (user #").Append(id).Append(')');
            text.Append('\n');
        }
        var result = text.ToString();
        return showLinkIds ? result : LinkIds().Replace(result, "$1[hidden]");
    }

    static async Task<IResult> GetAsync(HttpContext http, QhubDbContext db, TimeProvider time, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var since = request.Long("timestamp") ?? 0;
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var now = time.GetUtcNow();
        var entries = await RenderAsync(db, since == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(since), http.Caller().Has(UserPermissions.List), ct);
        return Results.Json(new { logEntries = entries, timestamp = now.ToUnixTimeSeconds() });
    }

    static async Task<IResult> DeleteAsync(HttpContext http, QhubDbContext db, TimeProvider time, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var before = request.Long("timestamp") ?? 0;
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var entries = db.AuditEntries.AsQueryable();
        if (before > 0)
        {
            var cutoff = DateTimeOffset.FromUnixTimeSeconds(before);
            entries = entries.Where(e => e.At < cutoff);
        }
        await entries.ExecuteDeleteAsync(ct);
        db.Audit(time.GetUtcNow(), http.Caller().User.Id, "LogsDeleted", null, before > 0 ? $"Logs older than {DateTimeOffset.FromUnixTimeSeconds(before):u} were deleted" : "All logs were deleted");
        await db.SaveChangesAsync(ct);
        return Results.Ok();
    }
}

/// <summary>Traffic written as it accrues (PLAN §5 #3), and the system status figures.</summary>
public sealed class ServerStats(IOptions<QhubOptions> options)
{
    readonly DateTimeOffset started = DateTimeOffset.UtcNow;
    TimeSpan lastCpu = Process.GetCurrentProcess().TotalProcessorTime;
    DateTime lastSample = DateTime.UtcNow;
    int lastLoad;

    public static Task RecordDownloadAsync(QhubDbContext db, DateTimeOffset now, long bytes, CancellationToken ct)
    {
        var day = DateOnly.FromDateTime(now.UtcDateTime);
        return db.Database.ExecuteSqlAsync($"""
            MERGE [TrafficStats] WITH (HOLDLOCK) AS t USING (SELECT {day} AS [Day]) AS s ON t.[Day] = s.[Day]
            WHEN MATCHED THEN UPDATE SET t.[BytesServed] = t.[BytesServed] + {bytes}, t.[Downloads] = t.[Downloads] + 1
            WHEN NOT MATCHED THEN INSERT ([Day], [BytesServed], [Downloads]) VALUES (s.[Day], {bytes}, 1);
            """, ct);
    }

    public int CpuLoad()
    {
        lock (this)
        {
            var now = DateTime.UtcNow;
            if ((now - lastSample).TotalSeconds >= 1)
            {
                var cpu = Process.GetCurrentProcess().TotalProcessorTime;
                lastLoad = (int)Math.Clamp((cpu - lastCpu).TotalMilliseconds / ((now - lastSample).TotalMilliseconds * Environment.ProcessorCount) * 100, 0, 100);
                (lastCpu, lastSample) = (cpu, now);
            }
            return lastLoad;
        }
    }

    public async Task<ServerStatus> SnapshotAsync(QhubDbContext db, DateTimeOffset now, CancellationToken ct)
    {
        var traffic = await db.TrafficStats.AsNoTracking().GroupBy(_ => 1)
            .Select(g => new { Bytes = g.Sum(t => t.BytesServed), Since = g.Min(t => t.Day) }).FirstOrDefaultAsync(ct);
        var activeFiles = await db.Links.CountAsync(l => l.State == LinkState.Live, ct);
        var memory = GC.GetGCMemoryInfo();
        var drive = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(options.Value.DataDir))!);
        long diskTotal = drive.TotalSize, diskUsed = drive.TotalSize - drive.AvailableFreeSpace;
        return new ServerStatus(
            (long)(now - started).TotalSeconds,
            traffic is null ? now.ToUnixTimeSeconds() : new DateTimeOffset(traffic.Since.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero).ToUnixTimeSeconds(),
            CpuLoad(),
            Percent(memory.MemoryLoadBytes, memory.TotalAvailableMemoryBytes),
            Percent(diskUsed, diskTotal),
            activeFiles,
            memory.MemoryLoadBytes,
            memory.TotalAvailableMemoryBytes,
            diskUsed,
            diskTotal,
            traffic?.Bytes ?? 0);
    }

    static int Percent(long part, long total) => total <= 0 ? 0 : (int)(part * 100 / total);
}

/// <summary>openapi <c>ServerStatus</c>.</summary>
public sealed record ServerStatus(long uptime, long trafficRecordingSince, int cpuLoad, int memoryUsagePercentage, int diskUsagePercentage,
    int activeFiles, long memoryUsed, long memoryTotal, long diskUsed, long diskTotal, long dataServed);
