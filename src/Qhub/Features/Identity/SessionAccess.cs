using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;

namespace Qhub.Features.Identity;

public static class SessionAccess
{
    public static bool IsInternalAuth(this QhubOptions o) => o.Auth.Contains("internal", StringComparison.OrdinalIgnoreCase);
    public static bool IsSamlAuth(this QhubOptions o) => o.Auth.Contains("saml", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A JSON endpoint of the admin pages: 401 without a session, 403 while a password change is pending (RULE-045 corrected).
    /// </summary>
    public static RouteHandlerBuilder RequiresSession(this RouteHandlerBuilder route) =>
        route.AddEndpointFilter(async (context, next) =>
        {
            var http = context.HttpContext;
            http.Response.Headers.CacheControl = "no-store, no-cache";
            var user = http.CurrentUser();
            if (user is null)
                return Results.Json(new { Result = "error", ErrorMessage = "Not authenticated" }, statusCode: StatusCodes.Status401Unauthorized);
            if (user.MustChangePassword && http.RequestServices.GetRequiredService<IOptions<QhubOptions>>().Value.IsInternalAuth())
                return Results.Json(new { Result = "error", ErrorMessage = "Password change required" }, statusCode: StatusCodes.Status403Forbidden);
            return await next(context);
        });

    /// <summary>303 to a page relative to the site root, as the legacy pages do.</summary>
    public static IActionResult SeeOther(this PageModel page, string relativeUrl)
    {
        page.Response.Headers.Location = "./" + relativeUrl;
        return new StatusCodeResult(StatusCodes.Status303SeeOther);
    }
}

/// <summary>A signed-in admin page; sends a user who must change the password to /changePassword (RULE-045 corrected, RULE-116).</summary>
public abstract class AdminPage : PageModel
{
    public User ActiveUser { get; private set; } = null!;
    protected virtual bool IsPasswordChangePage => false;

    public override async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        Response.Headers.CacheControl = "no-store, no-cache";
        var user = HttpContext.CurrentUser();
        if (user is null)
        {
            context.Result = this.SeeOther("login");
            return;
        }
        var options = HttpContext.RequestServices.GetRequiredService<IOptions<QhubOptions>>().Value;
        if (user.MustChangePassword && options.IsInternalAuth() && !IsPasswordChangePage)
        {
            context.Result = this.SeeOther("changePassword");
            return;
        }
        ActiveUser = user;
        ViewData["PublicName"] = options.PublicName;
        await next();
    }
}

/// <summary>The super admin is created or updated at every start (RULE-144).</summary>
public static class SuperAdmin
{
    public static async Task UpsertAsync(IServiceProvider services, CancellationToken ct)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<QhubDbContext>();
        var options = scope.ServiceProvider.GetRequiredService<IOptions<QhubOptions>>().Value;
        var passwords = scope.ServiceProvider.GetRequiredService<Passwords>();
        var name = options.AdminUser.ToLowerInvariant();

        var admin = await db.Users.FirstOrDefaultAsync(u => u.Rank == UserRank.SuperAdmin, ct);
        if (admin is null)
        {
            if (await db.Users.AnyAsync(ct))
                throw new InvalidOperationException("Could not edit superadmin: at least one user exists, but no superadmin found.");
            admin = new User { Name = name, Rank = UserRank.SuperAdmin, Permissions = UserPermissions.All, SecurityStamp = Passwords.NewSecurityStamp() };
            db.Users.Add(admin);
        }
        admin.Name = name;
        admin.Permissions = UserPermissions.All;
        if (options.IsInternalAuth() && !passwords.Verify(admin, options.AdminPassword))
        {
            // A new QHUB_ADMIN_PASSWORD ends the old sessions (the forgot-password page tells admins to do this).
            admin.PasswordHash = passwords.Hash(admin, options.AdminPassword);
            admin.SecurityStamp = Passwords.NewSecurityStamp();
            admin.MustChangePassword = false;
        }
        await db.SaveChangesAsync(ct);
    }
}
