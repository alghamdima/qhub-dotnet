namespace Qhub.Domain;

/// <summary>One business event. <see cref="LinkId"/> is redacted on read for readers without PERM_LIST (RULE-013).</summary>
public sealed class AuditEntry
{
    public long Id { get; set; }
    public DateTimeOffset At { get; set; }
    public int? ActorUserId { get; set; }
    public required string Action { get; set; }
    /// <summary>Not a foreign key: the entry outlives the link it records.</summary>
    public string? LinkId { get; set; }
    public string Detail { get; set; } = "";
    public string? ClientIp { get; set; }
}
