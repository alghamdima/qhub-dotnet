namespace Qhub.Domain;

public sealed class User
{
    public int Id { get; set; }
    public required string Name { get; set; }
    /// <summary><c>PasswordHasher</c> output; empty for SAML-only users, and an empty hash never verifies (RULE-063).</summary>
    public string PasswordHash { get; set; } = "";
    public UserRank Rank { get; set; }
    public UserPermissions Permissions { get; set; }
    public bool MustChangePassword { get; set; }
    /// <summary>Rotated to end all of the user's sessions (RULE-104).</summary>
    public required string SecurityStamp { get; set; }
    public DateTimeOffset? LastOnline { get; set; }
}

/// <summary>Legacy values (<c>internal/models/User.go</c>).</summary>
public enum UserRank
{
    SuperAdmin = 0,
    Admin = 1,
    User = 2,
}

/// <summary>Legacy bit values; the admin JS sends the <c>PERM_*</c> names.</summary>
[Flags]
public enum UserPermissions
{
    None = 0,
    Replace = 1,
    List = 2,
    Edit = 4,
    ReplaceOther = 8,
    Delete = 16,
    Logs = 32,
    Api = 64,
    Users = 128,
    All = 255,
}
