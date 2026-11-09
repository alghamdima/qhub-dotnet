namespace Qhub.Domain;

/// <summary>Wrong-code attempts for one link; 5 lock it for 24 hours (RULE-128, RULE-012 corrected).</summary>
public sealed class CodeLock
{
    public required string LinkId { get; set; }
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }
}
