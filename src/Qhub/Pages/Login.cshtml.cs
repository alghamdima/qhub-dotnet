using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Features.Audit;
using Qhub.Features.Identity;
using Qhub.Security;

namespace Qhub.Pages;

/// <summary>Login with username and password (RULE-043, RULE-063, RULE-149).</summary>
[IgnoreAntiforgeryToken] // checked below, so an expired form shows its own message (legacy IsFailedCsfr)
public sealed class LoginModel(QhubDbContext db, Passwords passwords, ClientThrottle throttle, IAntiforgery antiforgery,
    TimeProvider time, IOptions<QhubOptions> options) : PageModel
{
    public bool InternalLogin => options.Value.IsInternalAuth();
    public bool SamlLogin => options.Value.IsSamlAuth();
    public bool IsFailedLogin { get; private set; }
    public bool IsFailedCsrf { get; private set; }
    public string UserName { get; private set; } = "";

    public IActionResult OnGet()
    {
        ViewData["PublicName"] = options.Value.PublicName;
        Response.Headers.CacheControl = "no-store, no-cache";
        return HttpContext.CurrentUser() is null ? Page() : this.SeeOther("admin");
    }

    public async Task<IActionResult> OnPostAsync(string? username, string? password, CancellationToken ct)
    {
        ViewData["PublicName"] = options.Value.PublicName;
        Response.Headers.CacheControl = "no-store, no-cache";
        if (HttpContext.CurrentUser() is not null) return this.SeeOther("admin");
        UserName = username ?? "";
        if (!InternalLogin || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) return Page();

        if (!await throttle.WaitAsync(ThrottleKind.Login, HttpContext)) return StatusCode(StatusCodes.Status429TooManyRequests);
        IsFailedLogin = true;
        if (!await antiforgery.IsRequestValidAsync(HttpContext))
        {
            IsFailedCsrf = true; // nothing is logged for an expired form
            return Page();
        }

        var name = username.ToLowerInvariant();
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Name == name, ct);
        var now = time.GetUtcNow();
        if (!passwords.Verify(user, password))
        {
            db.Audit(now, null, "LoginFailed", null, $"Invalid login for user {username} by IP {HttpContext.Connection.RemoteIpAddress}");
            await db.SaveChangesAsync(ct);
            return Page();
        }
        db.Audit(now, user!.Id, "Login", null, $"{user.Name} logged in successfully");
        await db.SaveChangesAsync(ct);
        await Sessions.SignInAsync(HttpContext, user, singleSignOn: false);
        return this.SeeOther("admin");
    }
}
