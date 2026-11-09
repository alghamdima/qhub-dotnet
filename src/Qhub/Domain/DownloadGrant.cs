namespace Qhub.Domain;

/// <summary>A single-use, 30-second admin download grant bound to a user.</summary>
public sealed class DownloadGrant
{
    public required string Id { get; set; }
    public int UserId { get; set; }
    /// <summary>Comma-separated link IDs.</summary>
    public required string LinkIds { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
