namespace Qhub.Domain;

/// <summary>Marks a code pass whose download was already counted (RULE-007/109 corrected: once per pass, before the first byte).</summary>
public sealed class CountedPass
{
    public required string PassId { get; set; }
    public required string LinkId { get; set; }
    public DateTimeOffset CountedAt { get; set; }
}
