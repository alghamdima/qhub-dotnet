using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Security;

namespace Qhub.Tests.Support;

/// <summary>One app and one database shared by the customer-portal tests; each test seeds its own links and uses its own client IP.</summary>
public static partial class Portal
{
    static readonly SemaphoreSlim Gate = new(1, 1);
    static QhubFactory? factory;
    static int nextIp;

    public static async Task<QhubFactory> AppAsync()
    {
        await Gate.WaitAsync();
        try
        {
            if (factory is null)
            {
                var app = new QhubFactory(QhubFactory.ValidSettings(await SqlServer.NewDatabaseAsync()));
                app.CreateClient().Dispose(); // starts the app: migrations run once
                factory = app;
            }
            return factory;
        }
        finally { Gate.Release(); }
    }

    /// <summary>A browser: its own cookies, its own client IP, redirects not followed so tests see them.</summary>
    public static HttpClient Browser(this QhubFactory app, string? acceptLanguage = null, bool handleCookies = true)
    {
        var client = app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = handleCookies, BaseAddress = new Uri("https://localhost") });
        client.DefaultRequestHeaders.Add("X-Forwarded-For", $"203.0.113.{Interlocked.Increment(ref nextIp) % 250 + 1}");
        if (acceptLanguage is not null) client.DefaultRequestHeaders.Add("Accept-Language", acceptLanguage);
        return client;
    }

    public sealed record Seeded(string Id, byte[] Bytes, Guid ContentId);

    /// <summary>A live link with code <paramref name="code"/> and local content, or another state.</summary>
    public static async Task<Seeded> SeedLinkAsync(this QhubFactory app, string code = "4821", int? downloads = null,
        DateTimeOffset? expireAt = null, LinkState state = LinkState.Live, string fileName = "statement.pdf", Guid? sharedContent = null)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<QhubDbContext>();
        var owner = await db.Users.FirstOrDefaultAsync(u => u.Name == "owner");
        if (owner is null)
        {
            owner = new User { Name = "owner", SecurityStamp = "stamp", Rank = UserRank.User };
            db.Users.Add(owner);
            await db.SaveChangesAsync();
        }

        var id = LinkRules.NewId(15);
        byte[] bytes;
        StoredContent content;
        if (sharedContent is { } contentId)
        {
            content = await db.StoredContents.SingleAsync(c => c.Id == contentId);
            bytes = await File.ReadAllBytesAsync(Path.Combine(DataDir(scope), content.Location));
        }
        else
        {
            bytes = System.Text.Encoding.UTF8.GetBytes($"%PDF-fake content of {id} " + new string('x', 5000));
            content = new StoredContent { Id = Guid.NewGuid(), Location = id + ".bin", SizeBytes = bytes.Length, StoreKind = StoreKind.Local };
            await File.WriteAllBytesAsync(Path.Combine(DataDir(scope), content.Location), bytes);
            db.StoredContents.Add(content);
        }
        db.Links.Add(new Link
        {
            Id = id,
            OwnerId = owner.Id,
            ContentId = content.Id,
            FileName = fileName,
            ContentType = "application/pdf",
            AccessCodeMac = scope.ServiceProvider.GetRequiredService<AccessCodes>().Mac(code),
            State = state,
            DownloadsRemaining = downloads,
            ExpireAt = expireAt,
            UploadedAt = app.Time.GetUtcNow(),
        });
        await db.SaveChangesAsync();
        return new Seeded(id, bytes, content.Id);
    }

    static string DataDir(IServiceScope scope) => scope.ServiceProvider.GetRequiredService<IOptions<QhubOptions>>().Value.DataDir;

    public static Task<Link> LinkAsync(this QhubFactory app, string id) =>
        app.InDbAsync(db => db.Links.AsNoTracking().SingleAsync(l => l.Id == id));

    public static void AssertRedirect(HttpResponseMessage response, string location)
    {
        Assert.IsTrue(response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther, $"{response.StatusCode} instead of a redirect");
        Assert.AreEqual(location, response.Headers.Location?.OriginalString);
    }

    public static async Task<T> InDbAsync<T>(this QhubFactory app, Func<QhubDbContext, Task<T>> query)
    {
        using var scope = app.Services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<QhubDbContext>());
    }

    /// <summary>Opens the code form and posts <paramref name="code"/> as the page's script does.</summary>
    public static async Task<HttpResponseMessage> PostCodeAsync(this HttpClient browser, string id, string code)
    {
        var form = await browser.GetStringAsync($"/d?id={id}");
        var token = AntiforgeryToken().Match(form);
        Assert.IsTrue(token.Success, "the code form has an antiforgery token");
        return await browser.PostAsync($"/d?id={id}", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["password"] = code,
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value),
        }));
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}
