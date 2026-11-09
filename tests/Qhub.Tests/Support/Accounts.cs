using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Identity;

namespace Qhub.Tests.Support;

/// <summary>Staff accounts and signed-in admin browsers.</summary>
public static partial class Accounts
{
    static int next;

    public sealed record Account(int Id, string Name, string Password);

    public static async Task<Account> NewUserAsync(this QhubFactory app, UserPermissions permissions = UserPermissions.None, UserRank rank = UserRank.User,
        string? password = "user-password-1", bool mustChangePassword = false)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<QhubDbContext>();
        var user = new User
        {
            Name = $"user{Interlocked.Increment(ref next)}-{Guid.NewGuid():N}"[..30],
            Rank = rank,
            Permissions = permissions,
            SecurityStamp = Passwords.NewSecurityStamp(),
            MustChangePassword = mustChangePassword,
        };
        if (password is not null) user.PasswordHash = scope.ServiceProvider.GetRequiredService<Passwords>().Hash(user, password);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return new Account(user.Id, user.Name, password ?? "");
    }

    /// <summary>A browser signed in through the login page.</summary>
    public static async Task<HttpClient> SignInAsync(this QhubFactory app, Account account)
    {
        var browser = app.Browser();
        var response = await browser.LoginAsync(account.Name, account.Password);
        Portal.AssertRedirect(response, "./admin");
        return browser;
    }

    public static Task<HttpResponseMessage> LoginAsync(this HttpClient browser, string username, string password, bool withToken = true) =>
        browser.PostFormAsync("/login", "/login", new() { ["username"] = username, ["password"] = password }, withToken);

    /// <summary>Opens <paramref name="page"/>, then posts <paramref name="fields"/> with its antiforgery token.</summary>
    public static async Task<HttpResponseMessage> PostFormAsync(this HttpClient browser, string page, string action, Dictionary<string, string> fields, bool withToken = true)
    {
        var html = await browser.GetStringAsync(page);
        if (withToken)
        {
            var token = AntiforgeryToken().Match(html);
            Assert.IsTrue(token.Success, $"{page} has an antiforgery token");
            fields["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value);
        }
        return await browser.PostAsync(action, new FormUrlEncodedContent(fields));
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}
