using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Domain;

namespace Qhub.Features.Portal;

/// <summary>
/// The 5-minute pass a correct code earns, in cookie <c>p&lt;id&gt;</c> (RULE-125, RULE-146). It names its link and the link's
/// <see cref="Link.CodeStamp"/>, so a code change revokes it (RULE-065), and carries a pass ID so the download is counted once (RULE-007).
/// </summary>
public sealed class Passes(IDataProtectionProvider dataProtection, TimeProvider time, IOptions<QhubOptions> options)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    readonly IDataProtector protector = dataProtection.CreateProtector("Qhub.Portal.Pass.v1");

    public static string CookieName(string linkId) => "p" + linkId;

    public void Issue(HttpResponse response, Link link)
    {
        var now = time.GetUtcNow();
        var value = protector.Protect(string.Join('\n', link.Id, link.CodeStamp.ToString(CultureInfo.InvariantCulture),
            Guid.NewGuid().ToString("N"), now.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture)));
        response.Cookies.Append(CookieName(link.Id), value, new CookieOptions
        {
            Expires = now + Lifetime,
            HttpOnly = true,
            Secure = options.Value.PublicUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
            SameSite = SameSiteMode.Strict,
            Path = "/",
        });
    }

    /// <returns>The pass ID when the request carries a live pass for this link and its current code; otherwise null.</returns>
    public string? Validate(HttpRequest request, Link link)
    {
        if (request.Cookies[CookieName(link.Id)] is not { } value) return null;
        string plain;
        try { plain = protector.Unprotect(value); }
        catch (CryptographicException) { return null; }

        var parts = plain.Split('\n');
        if (parts.Length != 4 || parts[0] != link.Id || parts[1] != link.CodeStamp.ToString(CultureInfo.InvariantCulture)) return null;
        var issued = DateTimeOffset.FromUnixTimeMilliseconds(long.Parse(parts[3], CultureInfo.InvariantCulture));
        return time.GetUtcNow() < issued + Lifetime ? parts[2] : null;
    }
}
