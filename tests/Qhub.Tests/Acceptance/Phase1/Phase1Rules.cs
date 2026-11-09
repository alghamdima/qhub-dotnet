using System.Diagnostics;
using System.Net;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Domain;
using Qhub.Features.Portal;
using Qhub.Security;
using Qhub.Tests.Support;

namespace Qhub.Tests.Acceptance.Phase1;

/// <summary>Behavior Contract, Phase 1 (AI_NATIVE_SPEC.md §5): one test per rule, named after the rule ID.</summary>
[TestClass]
public sealed class Phase1Rules
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>RULE-001 Password hashing (user passwords and document codes) (legacy: internal/configuration/Configuration.go:175-226).</summary>
    /// <remarks>
    /// Given: code "1234" an empty code → stored as "" (no protection).<br/>
    /// When: it is stored<br/>
    /// Then: the value is "argon2id$" + hex(16-char salt) + "$" + hex(Argon2id("1234", salt, t=2, m=28 MiB, p=1, 32 bytes)).
    /// <br/>Reviewer: Keep the hashing (in .NET: PasswordHasher or Argon2). The code's strength is decided at Checkpoint 1.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-001")]
    public async Task RULE_001_PasswordsAndAccessCodesAreNeverStoredInPlainText()
    {
        // Access codes here; user passwords (PasswordHasher) are proven with Phase 3 identity.
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "1234");

        var stored = (await app.LinkAsync(link.Id)).AccessCodeMac!;

        var codes = app.Services.GetRequiredService<AccessCodes>();
        Assert.HasCount(32, stored);
        Assert.IsLessThan(0, stored.AsSpan().IndexOf("1234"u8), "the code is not in the stored value");
        Assert.IsTrue(codes.Verify("1234", stored));
        Assert.IsFalse(codes.Verify("1235", stored));
    }

    /// <summary>RULE-004 Link ID generation and length (legacy: internal/helper/StringGeneration.go:22-30).</summary>
    /// <remarks>
    /// Given: LENGTH_ID=15 LENGTH_ID=3 → raised to 5.<br/>
    /// When: a link is created<br/>
    /// Then: its ID is 15 characters from 62 symbols (≈89 bits), e.g. "aZ3k9QmP0xT7bLw".
    /// <br/>Reviewer: Keep random IDs and the length. The rebuild only inserts and never overwrites an existing link (a unique key).
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-004")]
    public async Task RULE_004_LinkIdIsRandomWithConfiguredLengthAndNeverOverwrites()
    {
        var id = LinkRules.NewId(15);
        Assert.AreEqual(15, id.Length);
        Assert.IsTrue(id.All(char.IsAsciiLetterOrDigit), id);
        Assert.AreEqual(5, LinkRules.NewId(3).Length, "LENGTH_ID=3 is raised to 5");
        Assert.AreNotEqual(LinkRules.NewId(15), LinkRules.NewId(15));

        var app = await Portal.AppAsync();
        var existing = await app.SeedLinkAsync();
        await Assert.ThrowsAsync<DbUpdateException>(() => app.InDbAsync(async db =>
        {
            var copy = await db.Links.AsNoTracking().SingleAsync(l => l.Id == existing.Id);
            copy.FileName = "overwritten.pdf";
            db.Links.Add(copy);
            return await db.SaveChangesAsync();
        }));
        Assert.AreEqual("statement.pdf", (await app.LinkAsync(existing.Id)).FileName);
    }

    /// <summary>RULE-010 When a link counts as expired (legacy: internal/storage/FileServing.go:832-837).</summary>
    /// <remarks>
    /// Given: a link with ExpireAt 2026-11-22 10:00:00 UTC, UnlimitedTime=false, DownloadsRemaining=1, UnlimitedDownloads=false<br/>
    /// When: it is checked at 2026-11-22 10:00:00 UTC, then at 10:00:01 UTC<br/>
    /// Then: it is valid at 10:00:00 and expired at 10:00:01. Separately, with DownloadsRemaining=0 it is expired at any time.
    /// <br/>Reviewer: The expiry definition is correct. The rebuild applies it to both lists.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-010")]
    public async Task RULE_010_LinkExpiresAfterExpireAtOrWhenNoDownloadsRemain()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(expireAt: app.Time.GetUtcNow(), downloads: 1);
        var usedUp = await app.SeedLinkAsync(downloads: 0);
        using var browser = app.Browser();

        var atExpiry = await browser.GetAsync($"/d?id={link.Id}");
        app.Time.Advance(TimeSpan.FromSeconds(1));
        var afterExpiry = await browser.GetAsync($"/d?id={link.Id}");
        var noDownloadsLeft = await browser.GetAsync($"/d?id={usedUp.Id}");

        Assert.AreEqual(HttpStatusCode.OK, atExpiry.StatusCode, "still valid at the exact ExpireAt");
        Portal.AssertRedirect(afterExpiry, "./error");
        Portal.AssertRedirect(noDownloadsLeft, "./error");
    }

    /// <summary>RULE-016 Per-IP rate limits (login, wrong code, unknown link, failed API key) (legacy: internal/webserver/ratelimiter/RateLimiter.go:55-120).</summary>
    /// <remarks>
    /// Given: one IP<br/>
    /// When: it submits logins rapidly → 3 are immediate, then 1 every 3 s (burst 9, cost 3). it submits download codes → 10 immediate, then 1 every 2 s (burst 20, cost 2). it requests unknown/expired link IDs → 10 immediate, then 1 per second (burst 10, cost 1). it fails API authentication → 200 immediate, then 1 per second (burst 200, cost 1).<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-016")]
    public async Task RULE_016_PerIpRateLimitsPerKind()
    {
        // The two customer kinds; the login and API-key kinds are proven with RULE-149 and RULE-147 in Phase 3.
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync();
        using var flooding = app.Browser();
        using var otherIp = app.Browser();

        var flood = await Task.WhenAll(Enumerable.Range(0, 30).Select(i => flooding.GetAsync($"/d?id=NotARealId{i:00}")));
        var otherIpUnknown = await otherIp.GetAsync("/d?id=NotARealId99");
        var sameIpCodeAttempt = await flooding.PostCodeAsync(link.Id, "1111");

        Assert.IsTrue(flood.Any(r => r.StatusCode == HttpStatusCode.TooManyRequests), "the flooding IP is refused once 10 are used and 3 wait");
        Assert.IsGreaterThanOrEqualTo(10, flood.Count(r => r.StatusCode == HttpStatusCode.Found));
        Portal.AssertRedirect(otherIpUnknown, "./error");
        Assert.AreEqual(HttpStatusCode.OK, sameIpCodeAttempt.StatusCode, "code attempts have their own bucket");
    }

    /// <summary>RULE-037 A database newer than the build is refused (legacy: internal/configuration/database/Database.go:63-82).</summary>
    /// <remarks>
    /// Given: database schema version 5 and a build supporting 4<br/>
    /// When: (not stated separately in the spec; the outcomes are given with each step above)<br/>
    /// Then: "Unable to continue" and exit 1
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-037")]
    public async Task RULE_037_DatabaseWithUnknownMigrationIsRefused()
    {
        var db = await SqlServer.NewDatabaseAsync();
        await using (var first = new QhubFactory(QhubFactory.ValidSettings(db)))
        {
            first.CreateClient().Dispose(); // creates the database and applies this build's migrations
        }
        await using (var connection = new SqlConnection(db))
        {
            await connection.OpenAsync(TestContext.CancellationToken);
            await using var insert = new SqlCommand(
                "INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES ('99991231235959_FromANewerBuild', '99.0.0')", connection);
            await insert.ExecuteNonQueryAsync(TestContext.CancellationToken);
        }

        await using var second = new QhubFactory(QhubFactory.ValidSettings(db));
        var failure = Assert.Throws<Exception>(() => second.CreateClient());

        Assert.Contains("Unable to continue", failure.ToString());
        Assert.Contains("99991231235959_FromANewerBuild", failure.ToString());
    }

    /// <summary>RULE-038 Settings checked at startup (all errors reported at once) (legacy: internal/configuration/setup/Setup.go:70-109).</summary>
    /// <remarks>
    /// Given: AUTH=internal, ADMIN_PASSWORD="abc", PUBLIC_URL="files.example.com"<br/>
    /// When: Qhub starts<br/>
    /// Then: it lists both errors and stops without saving the configuration
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-038")]
    public void RULE_038_AllSettingErrorsAreReportedAtOnce()
    {
        // Otherwise valid; the database is never reached because validation runs first.
        var settings = QhubFactory.ValidSettings("Server=unreachable.invalid;Database=unused;Connect Timeout=1");
        settings["QHUB_AUTH"] = "internal";
        settings["QHUB_ADMIN_PASSWORD"] = "abc";
        settings["QHUB_PUBLIC_URL"] = "files.example.com";
        using var factory = new QhubFactory(settings);

        var failure = Assert.Throws<Exception>(() => factory.CreateClient());

        var validation = FindInner<OptionsValidationException>(failure);
        Assert.IsNotNull(validation, failure.ToString());
        var errors = validation.Failures.ToList();
        Assert.HasCount(2, errors, string.Join(" | ", errors));
        Assert.IsTrue(errors.Any(e => e.StartsWith("QHUB_PUBLIC_URL", StringComparison.Ordinal)), string.Join(" | ", errors));
        Assert.IsTrue(errors.Any(e => e.StartsWith("QHUB_ADMIN_PASSWORD", StringComparison.Ordinal)), string.Join(" | ", errors));
    }

    static T? FindInner<T>(Exception? e) where T : Exception
    {
        for (; e is not null; e = e.InnerException)
        {
            if (e is T match) return match;
            if (e is AggregateException aggregate)
                return aggregate.InnerExceptions.Select(FindInner<T>).FirstOrDefault(x => x is not null);
        }
        return null;
    }

    /// <summary>RULE-042 Unknown or expired customer links show an error, with throttling per IP (legacy: internal/webserver/Webserver.go:240-244).</summary>
    /// <remarks>
    /// Given: IP X has opened 10 unknown IDs<br/>
    /// When: it opens /d?id=NotARealId99<br/>
    /// Then: the redirect to /error is delayed until a token is free
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-042")]
    public async Task RULE_042_UnknownLinkRedirectsToErrorWithPerIpThrottle()
    {
        var app = await Portal.AppAsync();
        using var browser = app.Browser();

        var clock = Stopwatch.StartNew();
        var responses = await Task.WhenAll(Enumerable.Range(0, 13).Select(i => browser.GetAsync($"/d?id=NotARealId{i:00}")));
        clock.Stop();

        // 10 tokens at once, then 1 per second: the 3 beyond 10 wait for tokens and are still redirected.
        foreach (var response in responses) Portal.AssertRedirect(response, "./error");
        Assert.IsGreaterThan(TimeSpan.FromSeconds(1.5), clock.Elapsed, "the redirects beyond 10 wait for a token");
    }

    /// <summary>RULE-044 The customer must enter the link's access code before downloading (legacy: internal/webserver/Webserver.go:519-556).</summary>
    /// <remarks>
    /// Given: link A with code 4821 and no pass cookie<br/>
    /// When: /d?id=A is opened password=1111 is posted password=4821 is posted<br/>
    /// Then: the code form is shown the form shows "wrong" with 4 attempts left and the attempt is logged the counter is cleared, cookie "pA" is set and the browser is redirected to d?id=A, which shows the download page
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-044")]
    public async Task RULE_044_CustomerMustEnterAccessCodeBeforeDownload()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "4821");
        using var browser = app.Browser();

        var form = await browser.GetStringAsync($"/d?id={link.Id}");
        var wrong = await (await browser.PostCodeAsync(link.Id, "1111")).Content.ReadAsStringAsync();
        var audited = await app.InDbAsync(db => db.AuditEntries.CountAsync(a => a.LinkId == link.Id && a.Action == "WrongCode"));
        var right = await browser.PostCodeAsync(link.Id, "4821");
        var page = await browser.GetStringAsync($"/d?id={link.Id}");

        Assert.Contains("Verify your identity", form);
        Assert.Contains("name=\"password\"", form);
        Assert.Contains("Incorrect code. Attempts left: 4", wrong);
        Assert.AreEqual(1, audited);
        Portal.AssertRedirect(right, $"./d?id={link.Id}");
        Assert.AreEqual(HttpStatusCode.SeeOther, right.StatusCode);
        var cookie = right.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith($"p{link.Id}=", StringComparison.Ordinal));
        Assert.Contains("httponly", cookie);
        Assert.Contains("samesite=strict", cookie);
        Assert.Contains("secure", cookie);
        Assert.Contains($"./downloadFile?id={link.Id}", page);
        Assert.Contains("statement.pdf", page);
        Assert.IsFalse(await app.InDbAsync(db => db.CodeLocks.AnyAsync(c => c.LinkId == link.Id)), "a correct code clears the counter");
    }

    /// <summary>RULE-065 Code passes are checked against their link and expiry, and revoked when the code changes (legacy: internal/webserver/authentication/downloadPasswordToken/DownloadPasswordToken.go:37-62).</summary>
    /// <remarks>
    /// Given: a pass for A issued at 10:00<br/>
    /// When: A's code is changed through /files/modify at 10:02<br/>
    /// Then: the pass is rejected at 10:03
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-065")]
    public async Task RULE_065_PassIsRevokedWhenCodeChanges()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "4821");
        using var browser = app.Browser();
        await browser.PostCodeAsync(link.Id, "4821");

        app.Time.Advance(TimeSpan.FromMinutes(2));
        await ChangeCodeAsync(app, link.Id, "7777");
        app.Time.Advance(TimeSpan.FromMinutes(1));

        Assert.Contains("Verify your identity", await browser.GetStringAsync($"/d?id={link.Id}"));
        Portal.AssertRedirect(await browser.GetAsync($"/downloadFile?id={link.Id}"), $"./d?id={link.Id}");
    }

    static async Task ChangeCodeAsync(QhubFactory app, string linkId, string code)
    {
        using var scope = app.Services.CreateScope();
        var mac = scope.ServiceProvider.GetRequiredService<AccessCodes>().Mac(code);
        await scope.ServiceProvider.GetRequiredService<CodeAttempts>().ChangeCodeAsync(linkId, mac, CancellationToken.None);
    }

    /// <summary>RULE-108 Link visibility states (live, reserved, pending deletion, expired, content missing) (legacy: internal/storage/FileServing.go:508-536).</summary>
    /// <remarks>
    /// Given: link "abc123xyz000000" with PendingDeletion = 0, not expired, SHA1 = "" (reserved) the same link with PendingDeletion = now+600<br/>
    /// When: GetLink and GetFile are called<br/>
    /// Then: GetLink returns it (QR code and filling still work), GetFile returns not-found (the customer cannot open it) both return not-found
    /// <br/>Reviewer: Correct, and hiding the link at scheduling time is the intended soft-delete behaviour.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-108")]
    public async Task RULE_108_LinkVisibilityStates()
    {
        var app = await Portal.AppAsync();
        var live = await app.SeedLinkAsync();
        var reserved = await app.SeedLinkAsync(state: LinkState.Reserved);
        var pending = await app.SeedLinkAsync(state: LinkState.PendingDeletion);
        var missingBlob = await app.SeedLinkAsync(code: "4821");
        using var browser = app.Browser();

        Assert.AreEqual(HttpStatusCode.OK, (await browser.GetAsync($"/d?id={live.Id}")).StatusCode);
        Portal.AssertRedirect(await browser.GetAsync($"/d?id={reserved.Id}"), "./error");
        Portal.AssertRedirect(await browser.GetAsync($"/d?id={pending.Id}"), "./error");

        await browser.PostCodeAsync(missingBlob.Id, "4821");
        var dataDir = app.Services.GetRequiredService<IOptions<QhubOptions>>().Value.DataDir;
        File.Delete(Path.Combine(dataDir, missingBlob.Id + ".bin"));
        Portal.AssertRedirect(await browser.GetAsync($"/downloadFile?id={missingBlob.Id}"), "./error");
        Assert.AreEqual(0, (await app.LinkAsync(missingBlob.Id)).DownloadCount, "content missing: nothing counted");
    }

    /// <summary>RULE-117 Customer download page states (/d) (legacy: internal/webserver/Webserver.go:490-560).</summary>
    /// <remarks>
    /// Given: link L with code "4821" and no valid cookie<br/>
    /// When: GET /d?id=L → the code form is shown POST password=1111 → the IP throttle waits, an attempt is counted, the form shows "wrong code, 4 attempts left", and the audit log records "Wrong password for file L by IP …" POST password=4821 → the counter is reset, cookie "pL" is set (5 min), and the browser is redirected to /d?id=L, which now shows the download page the ID is missing or shorter than 5 characters → the generic "file not found" error page the ID is unknown, expired, pending, reserved or has no content → the per-IP failed-ID throttle, then a redirect to /error<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-117")]
    public async Task RULE_117_DownloadPageStates()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "4821");
        using var english = app.Browser();
        using var arabic = app.Browser("ar-SA,ar;q=0.9,en;q=0.8");

        Portal.AssertRedirect(await english.GetAsync("/d"), "./error");
        Portal.AssertRedirect(await english.GetAsync("/d?id=abcd"), "./error");
        Portal.AssertRedirect(await english.GetAsync("/d?id=NotARealId99"), "./error");
        var englishForm = await english.GetStringAsync($"/d?id={link.Id}");
        var arabicForm = await arabic.GetStringAsync($"/d?id={link.Id}");
        var arabicError = await arabic.GetStringAsync("/error");
        await arabic.PostCodeAsync(link.Id, "4821");
        var arabicDownload = await arabic.GetStringAsync($"/d?id={link.Id}");

        Assert.Contains("lang=\"en\" dir=\"ltr\"", englishForm);
        Assert.Contains("lang=\"ar\" dir=\"rtl\"", arabicForm);
        Assert.Contains("التحقق من الهوية", arabicForm);
        Assert.Contains("الرابط غير صالح", arabicError);
        Assert.Contains("تحميل", arabicDownload);
        Assert.DoesNotContain("statement.pdf", arabicForm, "the file name stays hidden until the code is entered");
    }

    /// <summary>RULE-118 Customer file download endpoint (/downloadFile) (legacy: internal/webserver/Webserver.go:837-858).</summary>
    /// <remarks>
    /// Given: link L with a code and no "pL" cookie a valid cookie → ServeFile counts and serves the file. If the link expired between the check and the lock, the customer gets the throttled redirect to /error<br/>
    /// When: GET /downloadFile?id=L → redirect to /d?id=L, and nothing is counted<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-118")]
    public async Task RULE_118_DownloadFileWithoutPassRedirectsAndCountsNothing()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(downloads: 3);
        using var browser = app.Browser();

        Portal.AssertRedirect(await browser.GetAsync($"/downloadFile?id={link.Id}"), $"./d?id={link.Id}");
        Portal.AssertRedirect(await browser.GetAsync("/downloadFile?id=NotARealId99"), "./error");

        var after = await app.LinkAsync(link.Id);
        Assert.AreEqual(0, after.DownloadCount);
        Assert.AreEqual(3, after.DownloadsRemaining);
    }

    /// <summary>RULE-125 Code-entry token (short-lived download pass) (legacy: internal/webserver/authentication/downloadPasswordToken/DownloadPasswordToken.go:20-77).</summary>
    /// <remarks>
    /// Given: a token issued for link L at 10:00:00<br/>
    /// When: it is presented for L at 10:04:59 → valid; for link M → invalid; for L at 10:05:01 → invalid, and the token is deleted L's code is edited at 10:02 → every token for L is deleted<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// <br/>Reviewer: Keep the 5-minute pass. With counting fixed (RULE-109), every completed download counts.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-125")]
    public async Task RULE_125_PassIsValidForFiveMinutesForItsLinkOnly()
    {
        var app = await Portal.AppAsync();
        var l = await app.SeedLinkAsync(code: "4821");
        var m = await app.SeedLinkAsync(code: "4821");
        using var browser = app.Browser(handleCookies: false);
        var issued = await PassFor(app, l.Id, "4821");

        app.Time.Advance(TimeSpan.FromSeconds(4 * 60 + 59));
        var forL = await WithCookie(browser, $"/d?id={l.Id}", $"p{l.Id}={issued}");
        var forM = await WithCookie(browser, $"/d?id={m.Id}", $"p{m.Id}={issued}");
        app.Time.Advance(TimeSpan.FromSeconds(2));
        var expired = await WithCookie(browser, $"/d?id={l.Id}", $"p{l.Id}={issued}");

        Assert.Contains("./downloadFile?id=", forL);
        Assert.Contains("Verify your identity", forM);
        Assert.Contains("Verify your identity", expired);
    }

    static async Task<string> PassFor(QhubFactory app, string linkId, string code)
    {
        using var browser = app.Browser();
        var right = await browser.PostCodeAsync(linkId, code);
        var cookie = right.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith($"p{linkId}=", StringComparison.Ordinal));
        return cookie[(linkId.Length + 2)..cookie.IndexOf(';', StringComparison.Ordinal)];
    }

    static async Task<string> WithCookie(HttpClient browser, string url, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("Cookie", cookie);
        using var response = await browser.SendAsync(request);
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>RULE-128 Wrong-code counter and 24-hour document lock (legacy: internal/webserver/ratelimiter/RateLimiter.go:122-234).</summary>
    /// <remarks>
    /// Given: document H with no attempts 3 wrong codes, then a correct one → the counter is deleted<br/>
    /// When: 4 wrong codes are entered → attempts left shown as 4, 3, 2, 1 the 5th wrong code is entered at 10:00 → attempts left 0, LockedUntil = next day 10:00, and the audit entry adds "file locked after too many wrong passwords" any code (even a correct one) is entered before then → the "locked" view, with no check and no new count At or after next day 10:00 → a fresh 5 attempts<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// <br/>Reviewer: 5 attempts and a 24-hour lock are right. The rebuild stores the lock in the database (no fail-open); scope follows RULE-012.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-128")]
    public async Task RULE_128_FifthWrongCodeLocksLinkFor24Hours()
    {
        var app = await Portal.AppAsync();
        var h = await app.SeedLinkAsync(code: "4821");
        var other = await app.SeedLinkAsync(code: "4821");
        using var browser = app.Browser();
        using var second = app.Browser();

        for (var i = 0; i < 3; i++) await second.PostCodeAsync(other.Id, "1111");
        await second.PostCodeAsync(other.Id, "4821");
        Assert.IsFalse(await app.InDbAsync(db => db.CodeLocks.AnyAsync(c => c.LinkId == other.Id)), "3 wrong then a correct one: counter deleted");

        var left = new List<string>();
        for (var i = 0; i < 4; i++) left.Add(await (await browser.PostCodeAsync(h.Id, "1111")).Content.ReadAsStringAsync());
        var fifthAt = app.Time.GetUtcNow();
        var fifth = await (await browser.PostCodeAsync(h.Id, "1111")).Content.ReadAsStringAsync();
        var lockRow = await app.InDbAsync(db => db.CodeLocks.AsNoTracking().SingleAsync(c => c.LinkId == h.Id));
        var correctWhileLocked = await (await browser.PostCodeAsync(h.Id, "4821")).Content.ReadAsStringAsync();
        var afterCorrect = await app.InDbAsync(db => db.CodeLocks.AsNoTracking().SingleAsync(c => c.LinkId == h.Id));
        app.Time.Advance(CodeAttempts.LockTime);
        var afterLock = await (await browser.PostCodeAsync(h.Id, "1111")).Content.ReadAsStringAsync();

        for (var i = 0; i < 4; i++) Assert.Contains($"Attempts left: {4 - i}", left[i]);
        Assert.Contains("locked after 5 wrong attempts", fifth);
        Assert.AreEqual(fifthAt + CodeAttempts.LockTime, lockRow.LockedUntil, "locked until the same time next day");
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(a => a.LinkId == h.Id && a.Detail.EndsWith("file locked after too many wrong passwords"))));
        Assert.Contains("locked after 5 wrong attempts", correctWhileLocked);
        Assert.AreEqual(5, afterCorrect.FailedAttempts, "no check and no new count while locked");
        Assert.Contains("Attempts left: 4", afterLock);
    }

    [TestMethod]
    [TestCategory("RULE-128")]
    public async Task RULE_128_ParallelWrongCodesGetAtMostFiveChecks()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "4821");
        var browsers = Enumerable.Range(0, 12).Select(_ => app.Browser()).ToList();

        var pages = await Task.WhenAll(browsers.Select(async b => await (await b.PostCodeAsync(link.Id, "1111")).Content.ReadAsStringAsync()));

        Assert.AreEqual(4, pages.Count(p => p.Contains("Attempts left:", StringComparison.Ordinal)));
        Assert.AreEqual(8, pages.Count(p => p.Contains("locked after 5 wrong attempts", StringComparison.Ordinal)));
        Assert.AreEqual(5, (await app.InDbAsync(db => db.CodeLocks.AsNoTracking().SingleAsync(c => c.LinkId == link.Id))).FailedAttempts);
        browsers.ForEach(b => b.Dispose());
    }

    /// <summary>RULE-146 A correct code gives a 5-minute pass tied to that link (legacy: internal/webserver/Webserver.go:929-948).</summary>
    /// <remarks>
    /// Given: the right code entered for A at 10:00<br/>
    /// When: /downloadFile?id=A is opened at 10:04 it is opened at 10:06<br/>
    /// Then: the pass is accepted the customer is sent back to the code form
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-146")]
    public async Task RULE_146_CorrectCodeGivesFiveMinutePassForThatLink()
    {
        var app = await Portal.AppAsync();
        var a = await app.SeedLinkAsync(code: "4821");
        using var browser = app.Browser();
        await browser.PostCodeAsync(a.Id, "4821");

        app.Time.Advance(TimeSpan.FromMinutes(4));
        var at4 = await browser.GetAsync($"/downloadFile?id={a.Id}");
        app.Time.Advance(TimeSpan.FromMinutes(2));
        var at6 = await browser.GetAsync($"/downloadFile?id={a.Id}");

        Assert.AreEqual(HttpStatusCode.OK, at4.StatusCode);
        CollectionAssert.AreEqual(a.Bytes, await at4.Content.ReadAsByteArrayAsync());
        Portal.AssertRedirect(at6, $"./d?id={a.Id}");
    }

    /// <summary>RULE-150 Wrong-code attempts are throttled per IP (legacy: internal/webserver/ratelimiter/RateLimiter.go:65-68).</summary>
    /// <remarks>
    /// Given: IP X has made 10 code attempts in 5 s<br/>
    /// When: it makes attempt 11<br/>
    /// Then: it waits about 2 s before the code is checked
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-150")]
    public async Task RULE_150_WrongCodeAttemptsAreThrottledPerIp()
    {
        var app = await Portal.AppAsync();
        var links = new List<Portal.Seeded>();
        for (var i = 0; i < 5; i++) links.Add(await app.SeedLinkAsync(code: "4821"));
        var ids = links.Select(l => l.Id).ToList();
        using var browser = app.Browser();
        await browser.GetStringAsync($"/d?id={ids[0]}"); // one antiforgery cookie before the parallel posts

        // 4 per link, so no link locks: only the IP throttle acts.
        var posts = await Task.WhenAll(Enumerable.Range(0, 20).Select(i => browser.PostCodeAsync(ids[i % 5], "1111")));
        var checkedCodes = await app.InDbAsync(db => db.CodeLocks.Where(c => ids.Contains(c.LinkId)).SumAsync(c => c.FailedAttempts));

        var throttled = posts.Count(p => p.StatusCode == HttpStatusCode.TooManyRequests);
        Assert.IsGreaterThan(0, throttled, "attempts beyond 10 at once plus 3 waiting are refused");
        var statuses = string.Join(", ", posts.GroupBy(p => p.StatusCode).Select(g => $"{(int)g.Key}x{g.Count()}"));
        Assert.AreEqual(20 - throttled, checkedCodes, $"a refused attempt is never checked or counted ({statuses})");
    }

    /// <summary>RULE-007 (corrected) Download counting, as revised at Checkpoint 2: count once per pass, atomically, before the first byte; never below 0; ZIP included (legacy: internal/storage/FileServing.go:542-561).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/storage/FileServing.go:542-561, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: one download is counted once per code pass, atomically, before the first byte, and never below 0. Range resumes and the PDF viewer's range reads within the same 5-minute pass are not counted again; a link with 1 download is never served twice, even to parallel requests; the S3 redirect is counted; API downloads count per request when increaseCounter is set, and ZIP downloads count each member.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-007")]
    public async Task RULE_007_DownloadIsCountedOncePerPassBeforeFirstByte()
    {
        // The S3 redirect, API increaseCounter and ZIP parts are proven with Phase 2 storage and API.
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "4821", downloads: 1);
        using var browser = app.Browser();
        await browser.PostCodeAsync(link.Id, "4821");

        var full = await browser.GetAsync($"/downloadFile?id={link.Id}");
        using var rangeRequest = new HttpRequestMessage(HttpMethod.Get, $"/downloadFile?id={link.Id}");
        rangeRequest.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 9);
        var resume = await browser.SendAsync(rangeRequest);
        var after = await app.LinkAsync(link.Id);

        Assert.AreEqual(HttpStatusCode.OK, full.StatusCode);
        CollectionAssert.AreEqual(link.Bytes, await full.Content.ReadAsByteArrayAsync());
        Assert.AreEqual(HttpStatusCode.PartialContent, resume.StatusCode, "the same pass resumes after the last download");
        CollectionAssert.AreEqual(link.Bytes[..10], await resume.Content.ReadAsByteArrayAsync());
        Assert.AreEqual(1, after.DownloadCount);
        Assert.AreEqual(0, after.DownloadsRemaining);
    }

    [TestMethod]
    [TestCategory("RULE-007")]
    public async Task RULE_007_LastDownloadIsNeverServedTwiceInParallel()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "4821", downloads: 1);
        var browsers = Enumerable.Range(0, 6).Select(_ => app.Browser()).ToList();
        foreach (var b in browsers) await b.PostCodeAsync(link.Id, "4821");

        var downloads = await Task.WhenAll(browsers.Select(b => b.GetAsync($"/downloadFile?id={link.Id}")));
        var after = await app.LinkAsync(link.Id);

        Assert.AreEqual(1, downloads.Count(d => d.StatusCode == HttpStatusCode.OK));
        foreach (var refused in downloads.Where(d => d.StatusCode != HttpStatusCode.OK)) Portal.AssertRedirect(refused, "./error");
        Assert.AreEqual(1, after.DownloadCount);
        Assert.AreEqual(0, after.DownloadsRemaining, "never below 0");
        browsers.ForEach(b => b.Dispose());
    }

    /// <summary>RULE-012 (corrected) The wrong-code counter: lock per link, not per content. Changing the link's code lifts its lock, and the owner can unlock it (legacy: internal/webserver/Webserver.go:519-556).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/Webserver.go:519-556, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: The wrong-code counter: lock per link, not per content. Changing the link's code lifts its lock, and the owner can unlock it
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-012")]
    public async Task RULE_012_WrongCodeLockIsPerLinkAndLiftedByCodeChangeOrOwner()
    {
        var app = await Portal.AppAsync();
        var a = await app.SeedLinkAsync(code: "4821");
        var sameDocument = await app.SeedLinkAsync(code: "4821", sharedContent: a.ContentId);
        var c = await app.SeedLinkAsync(code: "4821");
        using var browser = app.Browser();
        using var second = app.Browser();
        for (var i = 0; i < 5; i++) await browser.PostCodeAsync(a.Id, "1111");
        for (var i = 0; i < 5; i++) await second.PostCodeAsync(c.Id, "1111");

        var copyStillOpen = await browser.PostCodeAsync(sameDocument.Id, "4821");
        await ChangeCodeAsync(app, a.Id, "7777");
        var afterCodeChange = await browser.PostCodeAsync(a.Id, "7777");
        using (var scope = app.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<CodeAttempts>().ResetAsync(c.Id, CancellationToken.None);
        var afterOwnerUnlock = await second.PostCodeAsync(c.Id, "4821");

        Assert.AreEqual(HttpStatusCode.SeeOther, copyStillOpen.StatusCode, "another link to the same document has its own counter");
        Assert.AreEqual(HttpStatusCode.SeeOther, afterCodeChange.StatusCode, "a new code lifts the lock");
        Assert.AreEqual(HttpStatusCode.SeeOther, afterOwnerUnlock.StatusCode, "the owner can unlock");
    }

    /// <summary>RULE-109 (corrected) Serving a download, as revised at Checkpoint 2: open the file and check the pass or key before sending, and count once per pass, atomically, before the first byte (legacy: internal/storage/FileServing.go:542-606).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/storage/FileServing.go:542-606, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: the file is opened and the pass or key is authorized before any byte is sent, and the download is counted once per pass, atomically, before the first byte. If the count fails (the link expired or has no downloads left) the customer is sent to /error and nothing is served.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-109")]
    public async Task RULE_109_DownloadIsAuthorizedAndCountedBeforeFirstByte()
    {
        var app = await Portal.AppAsync();
        var link = await app.SeedLinkAsync(code: "4821", downloads: 2, expireAt: app.Time.GetUtcNow().AddMinutes(1));
        using var browser = app.Browser();
        await browser.PostCodeAsync(link.Id, "4821");

        app.Time.Advance(TimeSpan.FromMinutes(2)); // the pass is still live, the link no longer is
        var refused = await browser.GetAsync($"/downloadFile?id={link.Id}");
        var after = await app.LinkAsync(link.Id);

        Portal.AssertRedirect(refused, "./error");
        Assert.IsEmpty(await refused.Content.ReadAsByteArrayAsync(), "nothing served");
        Assert.AreEqual(0, after.DownloadCount);
        Assert.AreEqual(2, after.DownloadsRemaining);
        Assert.IsFalse(await app.InDbAsync(db => db.CountedPasses.AnyAsync(p => p.LinkId == link.Id)), "a failed count leaves no pass row");
    }
}
