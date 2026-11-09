using System.Threading.RateLimiting;

namespace Qhub.Security;

public enum ThrottleKind
{
    /// <summary>Every code submitted on /d: 10 at once, then 1 every 2 s (RULE-016, RULE-150).</summary>
    CodeAttempt,
    /// <summary>Unknown or expired link IDs: 10 at once, then 1 per second (RULE-016, RULE-042).</summary>
    UnknownLink,
    /// <summary>Failed API authentication: 200 at once, then 1 per second (RULE-016, RULE-047).</summary>
    FailedApiKey,
    /// <summary>Login attempts: 3 at once, then 1 every 3 s (RULE-016, RULE-149).</summary>
    Login,
    /// <summary>A new chunked-upload ID: 4 at once, then 1 per second.</summary>
    NewUpload,
}

/// <summary>Per-IP token buckets. A request waits for a token; when 3 already wait, it is refused.</summary>
public sealed class ClientThrottle : IDisposable
{
    readonly Dictionary<ThrottleKind, PartitionedRateLimiter<string>> limiters = new()
    {
        [ThrottleKind.CodeAttempt] = PerIp(burst: 10, every: TimeSpan.FromSeconds(2)),
        [ThrottleKind.UnknownLink] = PerIp(burst: 10, every: TimeSpan.FromSeconds(1)),
        [ThrottleKind.FailedApiKey] = PerIp(burst: 200, every: TimeSpan.FromSeconds(1)),
        [ThrottleKind.Login] = PerIp(burst: 3, every: TimeSpan.FromSeconds(3)),
        [ThrottleKind.NewUpload] = PerIp(burst: 4, every: TimeSpan.FromSeconds(1)),
    };

    // A full bucket is dropped when idle, which is the same as never having seen the IP.
    static PartitionedRateLimiter<string> PerIp(int burst, TimeSpan every) =>
        PartitionedRateLimiter.Create<string, string>(ip => RateLimitPartition.GetTokenBucketLimiter(ip, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = burst,
            TokensPerPeriod = 1,
            ReplenishmentPeriod = every,
            QueueLimit = 3,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true,
        }));

    /// <returns>False when the IP already has 3 requests waiting: answer 429.</returns>
    public async ValueTask<bool> WaitAsync(ThrottleKind kind, HttpContext http)
    {
        using var lease = await limiters[kind].AcquireAsync(http.Connection.RemoteIpAddress?.ToString() ?? "", 1, http.RequestAborted);
        return lease.IsAcquired;
    }

    public void Dispose()
    {
        foreach (var limiter in limiters.Values) limiter.Dispose();
    }
}
