namespace Qhub.Domain;

/// <summary>A stored blob, deleted only when no link uses it (RULE-111).</summary>
public sealed class StoredContent
{
    public Guid Id { get; set; }
    /// <summary>HMAC-SHA-256(server key, bytes); null when deduplication is off (scope per brief Q3).</summary>
    public byte[]? DedupKey { get; set; }
    public long SizeBytes { get; set; }
    public StoreKind StoreKind { get; set; }
    public required string Location { get; set; }
    public bool Encrypted { get; set; }
    /// <summary>The per-content data key wrapped with the master key, when encrypted.</summary>
    public byte[]? WrappedKey { get; set; }
}

public enum StoreKind
{
    Local = 0,
    S3 = 1,
}
