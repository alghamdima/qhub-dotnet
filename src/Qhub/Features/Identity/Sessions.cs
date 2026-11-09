using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;

namespace Qhub.Features.Identity;

/// <summary>Passwords: <see cref="PasswordHasher{TUser}"/>; an empty hash never verifies (RULE-063).</summary>
public sealed class Passwords
{
    readonly PasswordHasher<User> hasher = new();
    readonly string dummyHash;

    public Passwords() => dummyHash = hasher.HashPassword(new User { Name = "", SecurityStamp = "" }, "qhub-dummy-password");

    public string Hash(User user, string password) => hasher.HashPassword(user, password);

    public bool Verify(User? user, string password)
    {
        if (user is null || user.PasswordHash.Length == 0)
        {
            // Same cost as a real check, so timing does not reveal which names exist.
            hasher.VerifyHashedPassword(new User { Name = "", SecurityStamp = "" }, dummyHash, password);
            return false;
        }
        return hasher.VerifyHashedPassword(user, user.PasswordHash, password) != PasswordVerificationResult.Failed;
    }

    public static string NewSecurityStamp() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    /// <summary>A random password of <paramref name="length"/> letters and digits.</summary>
    public static string Random(int length) =>
        RandomNumberGenerator.GetString("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", length);
}

/// <summary>
/// The admin session cookie (RULE-148, RULE-126 corrected): a password session is renewed every 12 hours and ends 30 days after
/// login at the latest; a single sign-on session lasts 12 hours. Rotating the user's security stamp ends every session.
/// </summary>
public static class Sessions
{
    public const string Scheme = CookieAuthenticationDefaults.AuthenticationScheme;
    public static readonly TimeSpan RenewAfter = TimeSpan.FromHours(12);
    public static readonly TimeSpan AbsoluteLimit = TimeSpan.FromDays(30);
    public static readonly TimeSpan SingleSignOnLifetime = TimeSpan.FromHours(12);

    const string UserIdClaim = "qhub:uid", StampClaim = "qhub:stamp", LoginClaim = "qhub:login", SsoClaim = "qhub:sso";

    public static void AddSessions(this IServiceCollection services)
    {
        services.AddAuthentication(Scheme).AddCookie(Scheme);
        services.AddOptions<CookieAuthenticationOptions>(Scheme).Configure<IOptions<QhubOptions>, TimeProvider>((o, q, time) =>
        {
            o.Cookie.Name = "session_token";
            o.Cookie.HttpOnly = true;
            o.Cookie.SameSite = SameSiteMode.Lax;
            o.Cookie.SecurePolicy = q.Value.PublicUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
            o.ExpireTimeSpan = AbsoluteLimit;
            o.SlidingExpiration = false;
            o.TimeProvider = time;
            o.Events.OnValidatePrincipal = ValidateAsync;
            // Pages and JSON endpoints answer for themselves; never redirect to the default /Account/Login.
            o.Events.OnRedirectToLogin = c => { c.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
            o.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };
        });
    }

    public static async Task SignInAsync(HttpContext http, User user, bool singleSignOn)
    {
        var now = http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();
        var identity = new ClaimsIdentity(
        [
            new Claim(UserIdClaim, user.Id.ToString(CultureInfo.InvariantCulture)),
            new Claim(StampClaim, user.SecurityStamp),
            new Claim(LoginClaim, now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
            new Claim(SsoClaim, singleSignOn ? "1" : "0"),
        ], Scheme);
        await http.SignInAsync(Scheme, new ClaimsPrincipal(identity), new AuthenticationProperties
        {
            IsPersistent = true,
            IssuedUtc = now,
            ExpiresUtc = now + (singleSignOn ? SingleSignOnLifetime : AbsoluteLimit),
        });
    }

    public static Task SignOutAsync(HttpContext http) => http.SignOutAsync(Scheme);

    /// <summary>The signed-in user, loaded once per request by <see cref="ValidateAsync"/>; null when not signed in.</summary>
    public static User? CurrentUser(this HttpContext http) => http.Items[typeof(Sessions)] as User;

    static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var http = context.HttpContext;
        var now = http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();
        var principal = context.Principal!;
        var id = int.Parse(principal.FindFirstValue(UserIdClaim)!, CultureInfo.InvariantCulture);
        var login = DateTimeOffset.FromUnixTimeSeconds(long.Parse(principal.FindFirstValue(LoginClaim)!, CultureInfo.InvariantCulture));
        var singleSignOn = principal.FindFirstValue(SsoClaim) == "1";

        var db = http.RequestServices.GetRequiredService<QhubDbContext>();
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, http.RequestAborted);
        if (user is null || user.SecurityStamp != principal.FindFirstValue(StampClaim) || now > login + AbsoluteLimit
            || (singleSignOn && now > login + SingleSignOnLifetime))
        {
            context.RejectPrincipal();
            await http.SignOutAsync(Scheme);
            return;
        }

        if (!singleSignOn && context.Properties.IssuedUtc is { } issued && now - issued > RenewAfter)
        {
            context.Properties.IssuedUtc = now;
            context.Properties.ExpiresUtc = login + AbsoluteLimit;
            context.ShouldRenew = true;
        }
        if (user.LastOnline is not { } seen || now - seen > TimeSpan.FromMinutes(1))
            await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.LastOnline, now), http.RequestAborted);
        http.Items[typeof(Sessions)] = user;
    }
}
