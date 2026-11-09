using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Qhub.Configuration;

namespace Qhub.Security;

/// <summary>
/// Customer codes are stored only as HMAC-SHA-256(server key, code) (RULE-001); the key never enters the database. The value is
/// not bound to the link, so a duplicate can keep the original's code (RULE-062).
/// </summary>
public sealed class AccessCodes(IOptions<QhubOptions> options)
{
    readonly byte[] key = Convert.FromBase64String(options.Value.ServerKey);

    public byte[] Mac(string code) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("qhub-access-code\n" + code));

    public bool Verify(string code, byte[]? mac) =>
        mac is not null && CryptographicOperations.FixedTimeEquals(Mac(code), mac);

    /// <summary>The code is the last 4 digits of the customer's ID, sent by the issuing system (brief Q2).</summary>
    public static bool IsValid(string? code) => code is { Length: 4 } && code.All(char.IsAsciiDigit);

    public const string InvalidMessage = "password is required: the last 4 digits of the customer's ID";
}
