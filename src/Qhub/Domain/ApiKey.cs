namespace Qhub.Domain;

public sealed class ApiKey
{
    /// <summary>Public ID; the secret is stored only as <see cref="SecretHash"/>.</summary>
    public required string Id { get; set; }
    public int OwnerId { get; set; }
    /// <summary>SHA-256 of the secret.</summary>
    public required byte[] SecretHash { get; set; }
    public string FriendlyName { get; set; } = "";
    /// <summary>A subset of the owner's permissions (RULE-049).</summary>
    public ApiPermissions Permissions { get; set; }
    /// <summary>Null = never expires.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? LastUsed { get; set; }
    /// <summary>A short-lived token for the admin JS (RULE-067).</summary>
    public bool IsSystemKey { get; set; }
}

/// <summary>Legacy bit values (<c>internal/models/ApiKey.go</c>); 256 stays unused.</summary>
[Flags]
public enum ApiPermissions
{
    None = 0,
    View = 1,
    Upload = 2,
    Delete = 4,
    ApiManage = 8,
    Edit = 16,
    Replace = 32,
    ManageUsers = 64,
    ManageLogs = 128,
    Download = 512,
    /// <summary>The default for keys created in the UI (RULE-005).</summary>
    Basic = View | Upload | Delete | Edit,
}
