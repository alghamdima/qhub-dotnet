using Microsoft.EntityFrameworkCore;
using Qhub.Data;
using Qhub.Domain;

namespace Qhub.Features.Portal;

/// <summary>The wrong-code counter, per link (RULE-128, RULE-012 corrected): 5 attempts, then the link is locked for 24 hours.</summary>
public sealed class CodeAttempts(QhubDbContext db, TimeProvider time)
{
    public const int MaxAttempts = 5;
    public static readonly TimeSpan LockTime = TimeSpan.FromHours(24);

    /// <summary>
    /// Takes one attempt before the code is checked, in one statement, so parallel posts get at most 5 checks in all.
    /// An expired lock starts a fresh count.
    /// </summary>
    /// <returns>The attempt number (1–5), or null while the link is locked.</returns>
    public async Task<int?> TryTakeAsync(string linkId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var lockedUntil = now + LockTime;
        var taken = await db.Database.SqlQuery<int>($"""
            MERGE [CodeLocks] WITH (HOLDLOCK) AS t
            USING (SELECT {linkId} AS [LinkId]) AS s ON t.[LinkId] = s.[LinkId]
            WHEN MATCHED AND (t.[LockedUntil] IS NULL OR t.[LockedUntil] <= {now}) THEN UPDATE SET
                t.[FailedAttempts] = CASE WHEN t.[LockedUntil] IS NULL THEN t.[FailedAttempts] + 1 ELSE 1 END,
                t.[LockedUntil] = CASE WHEN t.[LockedUntil] IS NULL AND t.[FailedAttempts] + 1 >= {MaxAttempts} THEN {lockedUntil} END
            WHEN NOT MATCHED THEN INSERT ([LinkId], [FailedAttempts]) VALUES (s.[LinkId], 1)
            OUTPUT inserted.[FailedAttempts] AS [Value];
            """).ToListAsync(ct);
        return taken.Count == 0 ? null : taken[0];
    }

    /// <summary>A correct code, or the owner unlocking the link (RULE-012), clears the counter.</summary>
    public Task ResetAsync(string linkId, CancellationToken ct) =>
        db.CodeLocks.Where(c => c.LinkId == linkId).ExecuteDeleteAsync(ct);

    /// <summary>A new code revokes every pass (RULE-065) and lifts the lock (RULE-012).</summary>
    public async Task ChangeCodeAsync(string linkId, byte[] newMac, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.Links.Where(l => l.Id == linkId).ExecuteUpdateAsync(s => s
            .SetProperty(l => l.AccessCodeMac, newMac)
            .SetProperty(l => l.CodeStamp, l => l.CodeStamp + 1), ct);
        await ResetAsync(linkId, ct);
        await tx.CommitAsync(ct);
    }
}
