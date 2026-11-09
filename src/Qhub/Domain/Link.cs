namespace Qhub.Domain;

/// <summary>A customer link (<c>/d?id=</c>). It points to its content, which may be shared with other links.</summary>
public sealed class Link
{
    public required string Id { get; set; }
    public int OwnerId { get; set; }
    /// <summary>Null while <see cref="LinkState.Reserved"/>.</summary>
    public Guid? ContentId { get; set; }
    public string FileName { get; set; } = "";
    public string ContentType { get; set; } = "";
    /// <summary>HMAC-SHA-256(server key, id + code). Required once the link is not reserved.</summary>
    public byte[]? AccessCodeMac { get; set; }
    /// <summary>Bumped on a code change, replace or owner unlock; revokes every issued pass.</summary>
    public int CodeStamp { get; set; }
    public LinkState State { get; set; }
    public DateTimeOffset? ReservedUntil { get; set; }
    /// <summary>Null = unlimited time.</summary>
    public DateTimeOffset? ExpireAt { get; set; }
    /// <summary>Null = unlimited downloads.</summary>
    public int? DownloadsRemaining { get; set; }
    public int DownloadCount { get; set; }
    /// <summary>When a <see cref="LinkState.PendingDeletion"/> link is deleted.</summary>
    public DateTimeOffset? DeleteAt { get; set; }
    public DateTimeOffset? UploadedAt { get; set; }
}

public enum LinkState
{
    Reserved = 0,
    Live = 1,
    PendingDeletion = 2,
}
