using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;

namespace Qhub.Features.Uploads;

/// <summary>Legacy <c>processingstatus</c> values the admin page reads.</summary>
public static class UploadStatus
{
    public const int Processing = 0, Saving = 1, Finished = 2, Error = 3;
}

/// <summary>
/// Live events for the signed-in user's open admin pages (<c>/uploadStatus</c>, spec §3.3): upload status and download counts.
/// Statuses are kept for 24 hours and replayed to a page that connects later.
/// </summary>
public sealed class UploadStatusHub(TimeProvider time)
{
    sealed record Listener(int UserId, Channel<string> Channel);
    sealed record Kept(int UserId, string Json, DateTimeOffset At);

    readonly ConcurrentDictionary<Guid, Listener> listeners = new();
    readonly ConcurrentDictionary<string, Kept> statuses = new();

    public void SetStatus(int userId, string chunkId, int status, string fileId = "", string error = "")
    {
        var json = JsonSerializer.Serialize(new { @event = "uploadStatus", chunk_id = chunkId, file_id = fileId, error_message = error, upload_status = status });
        statuses[$"{userId}/{chunkId}"] = new Kept(userId, json, time.GetUtcNow());
        Publish(userId, json);
    }

    /// <summary>Unlimited downloads are sent as -1, as the page expects.</summary>
    public void Downloaded(int userId, string linkId, int downloadCount, int? downloadsRemaining) =>
        Publish(userId, JsonSerializer.Serialize(new { @event = "download", file_id = linkId, download_count = downloadCount, downloads_remaining = downloadsRemaining ?? -1 }));

    /// <summary>A new listener: the user's kept statuses first, then live events.</summary>
    public (ChannelReader<string> Events, IDisposable Subscription) Subscribe(int userId)
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(64) { FullMode = BoundedChannelFullMode.DropOldest });
        var cutoff = time.GetUtcNow().AddHours(-24);
        foreach (var (key, kept) in statuses)
        {
            if (kept.At < cutoff) statuses.TryRemove(key, out _);
            else if (kept.UserId == userId) channel.Writer.TryWrite(kept.Json);
        }
        listeners[id] = new Listener(userId, channel);
        return (channel.Reader, new Unsubscribe(() => listeners.TryRemove(id, out _)));
    }

    void Publish(int userId, string json)
    {
        foreach (var listener in listeners.Values)
            if (listener.UserId == userId) listener.Channel.Writer.TryWrite(json);
    }

    sealed class Unsubscribe(Action action) : IDisposable
    {
        public void Dispose() => action();
    }
}
