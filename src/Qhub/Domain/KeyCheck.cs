namespace Qhub.Domain;

/// <summary>The single row that lets startup verify the encryption password and mode (RULE-002, RULE-039).</summary>
public sealed class KeyCheck
{
    public int Id { get; set; } = 1;
    public required byte[] Salt { get; set; }
    public required byte[] Verifier { get; set; }
    /// <summary>"none" or "on".</summary>
    public required string Mode { get; set; }
}
