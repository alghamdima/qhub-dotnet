using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Features.Audit;
using Qhub.Features.Identity;

namespace Qhub.Pages;

/// <summary>The forced password change after a reset (RULE-116): ends every session, then signs in again.</summary>
public sealed class ChangePasswordModel(QhubDbContext db, Passwords passwords, TimeProvider time, IOptions<QhubOptions> options) : AdminPage
{
    protected override bool IsPasswordChangePage => true;
    public int MinPasswordLength => options.Value.MinLengthPassword;
    public string ErrorMessage { get; private set; } = "";

    public IActionResult OnGet() => ActiveUser.MustChangePassword ? Page() : this.SeeOther("admin");

    public async Task<IActionResult> OnPostAsync(string? newpw, CancellationToken ct)
    {
        if (!ActiveUser.MustChangePassword) return this.SeeOther("admin");
        if (string.IsNullOrEmpty(newpw)) return Page();
        if (newpw.Length < MinPasswordLength)
        {
            ErrorMessage = "Password is too short";
            return Page();
        }
        var user = await db.Users.SingleAsync(u => u.Id == ActiveUser.Id, ct);
        if (passwords.Verify(user, newpw))
        {
            ErrorMessage = "New password has to be different from the old password";
            return Page();
        }
        user.PasswordHash = passwords.Hash(user, newpw);
        user.MustChangePassword = false;
        user.SecurityStamp = Passwords.NewSecurityStamp(); // every other session ends
        db.Audit(time.GetUtcNow(), user.Id, "PasswordChanged", null, $"{user.Name} (#{user.Id}) changed the password");
        await db.SaveChangesAsync(ct);
        await Sessions.SignInAsync(HttpContext, user, singleSignOn: false);
        return this.SeeOther("admin");
    }
}
