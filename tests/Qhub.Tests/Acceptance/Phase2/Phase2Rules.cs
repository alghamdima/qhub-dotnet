using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Domain;
using Qhub.Features.Retention;
using Qhub.Features.Uploads;
using Qhub.Tests.Support;

namespace Qhub.Tests.Acceptance.Phase2;

/// <summary>Behavior Contract, Phase 2 (AI_NATIVE_SPEC.md §5): one test per rule, named after the rule ID.</summary>
[TestClass]
public sealed class Phase2Rules
{
    /// <summary>RULE-002 The encryption mode cannot change while encrypted files exist (legacy: internal/configuration/setup/Setup.go:148-183).</summary>
    /// <remarks>
    /// Given: the previous level "full" with 1 encrypted file<br/>
    /// When: the server starts with QHUB_ENCRYPTION=none<br/>
    /// Then: startup fails with "Set it back to "full", or delete the encrypted files first".
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-002")]
    public async Task RULE_002_EncryptionModeCannotChangeWhileEncryptedContentExists()
    {
        var fixture = await Encrypted.Value;

        var failure = StartFails(fixture.Settings(encryption: "none"));

        Assert.Contains("Set it back to \"on\", or delete the encrypted files first", failure.ToString());
    }

    /// <summary>RULE-003 Encryption key derivation and file keys (legacy: internal/encryption/Encryption.go:46-132).</summary>
    /// <remarks>
    /// Given: QHUB_ENCRYPTION=full-password and QHUB_ENCRYPTION_PASSWORD set<br/>
    /// When: the server starts<br/>
    /// Then: master = scrypt(pw, Salt, N=1048576, r=8, p=1, 32 bytes). If sha256(scrypt(pw, ChecksumSalt, same parameters)) ≠ the stored Checksum, startup stops.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-003")]
    public async Task RULE_003_EncryptionKeyIsDerivedAndVerifiedAtStart()
    {
        var fixture = await Encrypted.Value;
        await using var restarted = new QhubFactory(fixture.Settings());
        using var caller = await restarted.NewCallerAsync(UserPermissions.List);

        var check = await restarted.InDbAsync(db => db.KeyChecks.AsNoTracking().SingleAsync());
        using var download = await caller.SendAsync(HttpMethod.Get, $"/api/files/download/{fixture.LinkId}");

        Assert.AreEqual("on", check.Mode);
        Assert.HasCount(16, check.Salt);
        Assert.HasCount(32, check.Verifier);
        CollectionAssert.AreEqual(fixture.Bytes, await download.Content.ReadAsByteArrayAsync(), "the same password decrypts after a restart");
    }

    /// <summary>RULE-008 Reusing stored content and its encryption key (legacy: internal/storage/FileServing.go:55-131).</summary>
    /// <remarks>
    /// Given: encryption "full", a stored object for hash H and an existing link L1 with key K1 object H exists but no link references it → the object is overwritten and L2 gets a new key.<br/>
    /// When: the same PDF is uploaded again<br/>
    /// Then: the new link L2 uses object H and key K1, and no new object is written.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-008")]
    public async Task RULE_008_IdenticalContentIsReusedWithItsKey()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var bytes = Api.Pdf(tag: "008");

        var first = await caller.AddAsync(bytes);
        var blobsBefore = Blobs(app).Count;
        var second = await caller.AddAsync(bytes);

        var contents = await app.InDbAsync(db => db.Links.Where(l => l.Id == Id(first) || l.Id == Id(second)).Select(l => l.ContentId).Distinct().ToListAsync());
        Assert.AreNotEqual(Id(first), Id(second));
        Assert.HasCount(1, contents, "both links use one stored object");
        Assert.AreEqual(blobsBefore, Blobs(app).Count, "no new object is written");
    }

    /// <summary>RULE-009 Hourly clean-up of expired links and unreferenced content (legacy: internal/storage/FileServing.go:736-767).</summary>
    /// <remarks>
    /// Given: links L1 (expired) and L2 (active) sharing hash H<br/>
    /// When: the clean-up runs<br/>
    /// Then: L1's row is deleted and object H is kept. When L2 later expires, its row and object H are deleted.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-009")]
    public async Task RULE_009_CleanupDeletesExpiredLinksAndUnreferencedContent()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var bytes = Api.Pdf(tag: "009");
        var l1 = Id(await caller.AddAsync(bytes, ("expiryMinutes", "1")));
        var l2 = Id(await caller.AddAsync(bytes));
        var content = (await app.LinkAsync(l2)).ContentId!.Value;

        app.Time.Advance(TimeSpan.FromMinutes(2));
        await RunCleanupAsync(app);
        var afterL1 = await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == l1));
        var contentKept = await app.InDbAsync(db => db.StoredContents.AnyAsync(c => c.Id == content));
        await app.InDbAsync(db => db.Links.Where(l => l.Id == l2).ExecuteUpdateAsync(x => x.SetProperty(l => l.DownloadsRemaining, 0)));
        await RunCleanupAsync(app);

        Assert.IsFalse(afterL1, "the expired link is deleted");
        Assert.IsTrue(contentKept, "its content stays while L2 uses it");
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == l2)));
        Assert.IsFalse(await app.InDbAsync(db => db.StoredContents.AnyAsync(c => c.Id == content)), "the last link gone: content deleted");
    }

    /// <summary>RULE-011 Immediate and scheduled deletion, and restore (legacy: internal/storage/FileServing.go:870-946).</summary>
    /// <remarks>
    /// Given: /files/delete with delay=60 at 10:00:00<br/>
    /// When: nothing else happens /files/restore is called at 10:00:30 → PendingDeletion=0 and the link works again.<br/>
    /// Then: PendingDeletion=10:01:00, the customer link is unreachable at once, and at 10:01:00 the link is deleted and its content removed if no other link uses it.
    /// <br/>Reviewer: Keep soft delete with restore. The rebuild rejects a negative delay.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-011")]
    public async Task RULE_011_ImmediateAndScheduledDeletionAndRestore()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        using var browser = app.Browser();
        var id = Id(await caller.AddAsync(Api.Pdf(tag: "011")));

        await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", id), ("delay", "60"));
        var hidden = await browser.GetAsync($"/d?id={id}");
        app.Time.Advance(TimeSpan.FromSeconds(30));
        using var restore = await caller.SendAsync(HttpMethod.Post, "/api/files/restore", ("id", id));
        var back = await browser.GetAsync($"/d?id={id}");
        await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", id), ("delay", "60"));
        app.Time.Advance(TimeSpan.FromSeconds(61));
        await RunCleanupAsync(app);

        Portal.AssertRedirect(hidden, "./error");
        Assert.AreEqual(HttpStatusCode.OK, restore.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, back.StatusCode, "the link works again");
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == id)), "deleted once the delay passed");
        using var negative = await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", Id(await caller.AddAsync(Api.Pdf()))), ("delay", "-1"));
        Assert.AreEqual(HttpStatusCode.BadRequest, negative.StatusCode, "a negative delay is refused");
    }

    /// <summary>RULE-015 Upload parameters for a single-request upload (/files/add): defaults, unlimited sentinels, expiry formula (legacy: internal/webserver/fileupload/FileUpload.go:105-165).</summary>
    /// <remarks>
    /// Given: an upload at 2026-11-08 10:00:00 UTC with allowedDownloads absent, expiryDays absent, password "1234" expiryDays=0 → UnlimitedTime=true. Given allowedDownloads=0 → UnlimitedDownloads=true. expiryMinutes=30 → ExpireAt=2026-11-08 10:30:00 UTC and UnlimitedTime is forced to false, even if expiryDays=0 or isUnlimitedTime=true.<br/>
    /// When: the upload is processed<br/>
    /// Then: DownloadsRemaining=1, ExpireAt=2026-11-22 10:00:00 UTC, UnlimitedTime=false.
    /// <br/>Reviewer: The defaults and the meaning of 0 are correct. The rebuild caps the day value.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-015")]
    public async Task RULE_015_SingleRequestUploadDefaultsAndExpiryFormula()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var now = app.Time.GetUtcNow();

        var defaults = await caller.AddAsync(Api.Pdf());
        var noTime = await caller.AddAsync(Api.Pdf(), ("expiryDays", "0"));
        var noLimit = await caller.AddAsync(Api.Pdf(), ("allowedDownloads", "0"));
        var minutes = await caller.AddAsync(Api.Pdf(), ("expiryMinutes", "30"), ("expiryDays", "0"), ("isUnlimitedTime", "true"));

        Assert.AreEqual(1, defaults.GetProperty("DownloadsRemaining").GetInt32());
        Assert.IsFalse(defaults.GetProperty("UnlimitedDownloads").GetBoolean());
        Assert.AreEqual(now.AddDays(14).ToUnixTimeSeconds(), defaults.GetProperty("ExpireAt").GetInt64());
        Assert.IsFalse(defaults.GetProperty("UnlimitedTime").GetBoolean());
        Assert.IsTrue(noTime.GetProperty("UnlimitedTime").GetBoolean(), "expiryDays=0 is unlimited time");
        Assert.IsTrue(noLimit.GetProperty("UnlimitedDownloads").GetBoolean(), "allowedDownloads=0 is unlimited downloads");
        Assert.AreEqual(now.AddMinutes(30).ToUnixTimeSeconds(), minutes.GetProperty("ExpireAt").GetInt64());
        Assert.IsFalse(minutes.GetProperty("UnlimitedTime").GetBoolean(), "expiryMinutes is always limited");
    }

    /// <summary>RULE-039 Encryption keys are checked at start (legacy: internal/encryption/Encryption.go:50-120).</summary>
    /// <remarks>
    /// Given: ENCRYPTION=full-password set up with password P<br/>
    /// When: Qhub starts with a different password<br/>
    /// Then: it stops with "QHUB_ENCRYPTION_PASSWORD is not the password Qhub was set up with"
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-039")]
    public async Task RULE_039_WrongEncryptionPasswordIsRefusedAtStart()
    {
        var fixture = await Encrypted.Value;

        var failure = StartFails(fixture.Settings(password: "a-different-password-9999"));

        Assert.Contains("QHUB_ENCRYPTION_PASSWORD is not the password Qhub was set up with", failure.ToString());
    }

    /// <summary>RULE-040 Chunks are private to the uploader (legacy: internal/storage/chunking/Chunking.go:159-204).</summary>
    /// <remarks>
    /// Given: user #5 uploaded chunks with uuid "abcdef1234"<br/>
    /// When: user #9 calls /chunk/complete with uuid "abcdef1234"<br/>
    /// Then: 400 "chunk file does not exist"
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-040")]
    public async Task RULE_040_ChunksArePrivateToTheUploader()
    {
        var app = await Portal.AppAsync();
        using var owner = await app.NewCallerAsync();
        using var other = await app.NewCallerAsync();
        var bytes = Api.Pdf(4000);
        await AddChunkAsync(owner, "abcdef1234", 0, bytes);

        using var stolen = await CompleteAsync(other, "abcdef1234", bytes.Length);
        using var own = await CompleteAsync(owner, "abcdef1234", bytes.Length);

        Api.AssertError(stolen, HttpStatusCode.BadRequest, 0, await stolen.JsonAsync(), "chunk file does not exist");
        Assert.AreEqual(HttpStatusCode.OK, own.StatusCode, (await own.JsonAsync()).ToString());
    }

    /// <summary>RULE-068 /api/files/add and /api/files/content refuse a document without an access code (legacy: internal/webserver/fileupload/FileUpload.go:132-138).</summary>
    /// <remarks>
    /// Given: a multipart upload to /api/files/add with file "statement.pdf" and no `password` field<br/>
    /// When: it is processed<br/>
    /// Then: the API answers 400 ErrorCode UnspecifiedError(0) "password is required: the last 4 digits of the customer's ID" and no link is created And with `password=4821` the link is created and the code is stored as an Argon2id hash
    /// <br/>Reviewer: Refusing a document without a code is right. The code's format and strength are decided at Checkpoint 1.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-068")]
    public async Task RULE_068_UploadWithoutAccessCodeIsRefused()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();

        using var refused = await caller.Client.PostAsync("/api/files/add", Api.Upload(Api.Pdf()));
        var none = await app.InDbAsync(db => db.Links.CountAsync(l => l.OwnerId == caller.UserId));
        var created = await caller.AddAsync(Api.Pdf(), ("password", "4821"));

        Api.AssertError(refused, HttpStatusCode.BadRequest, 0, await refused.JsonAsync(), "password is required: the last 4 digits of the customer's ID");
        Assert.AreEqual(0, none, "no link is created");
        Assert.HasCount(32, (await app.LinkAsync(Id(created))).AccessCodeMac!, "the code is stored hashed");
    }

    /// <summary>RULE-105 Database query for clean-up candidates (legacy: internal/configuration/database/provider/postgres/metadata.go:109-113).</summary>
    /// <remarks>
    /// Given: rows A (UnlimitedTime=0, ExpireAt=now-1), B (UnlimitedDownloads=0, DownloadsRemaining=0), C (PendingDeletion=now-5) and D (PendingDeletion=now+600, not expired)<br/>
    /// When: GetExpiredMetadata(now) runs<br/>
    /// Then: A, B and C are returned and D is not
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-105")]
    public async Task RULE_105_CleanupSelectsExpiredExhaustedAndDueLinks()
    {
        var app = await Portal.AppAsync();
        var now = app.Time.GetUtcNow();
        var a = await app.SeedLinkAsync(expireAt: now.AddSeconds(-1));
        var b = await app.SeedLinkAsync(downloads: 0);
        var c = await app.SeedLinkAsync(state: LinkState.PendingDeletion);
        var d = await app.SeedLinkAsync(state: LinkState.PendingDeletion);
        var live = await app.SeedLinkAsync();
        var reserved = await app.SeedLinkAsync(state: LinkState.Reserved);
        await app.InDbAsync(async db =>
        {
            await db.Links.Where(l => l.Id == c.Id).ExecuteUpdateAsync(x => x.SetProperty(l => l.DeleteAt, now.AddSeconds(-5)));
            await db.Links.Where(l => l.Id == d.Id).ExecuteUpdateAsync(x => x.SetProperty(l => l.DeleteAt, now.AddSeconds(600)));
            return await db.Links.Where(l => l.Id == reserved.Id).ExecuteUpdateAsync(x => x.SetProperty(l => l.ReservedUntil, now.AddSeconds(-1)));
        });
        var seeded = new[] { a.Id, b.Id, c.Id, d.Id, live.Id, reserved.Id };

        using var scope = app.Services.CreateScope();
        var selected = await scope.ServiceProvider.GetRequiredService<Cleanup>().Candidates(now).Where(l => seeded.Contains(l.Id)).Select(l => l.Id).ToListAsync();

        CollectionAssert.AreEquivalent(new[] { a.Id, b.Id, c.Id, reserved.Id }, selected);
    }

    /// <summary>RULE-107 Reserving a link before its document exists (legacy: internal/storage/FileServing.go:490-506).</summary>
    /// <remarks>
    /// Given: user 7 calls /files/reserve at 10:00<br/>
    /// When: the reservation is saved<br/>
    /// Then: a new random ID (15 characters by default) exists with SHA1 = "", UserId = 7, ExpireAt = 11:00, UnlimitedDownloads = true, and an audit entry "ID … reserved by …" is written And if no document arrives by 11:00, the hourly clean-up deletes the row
    /// <br/>Reviewer: Reserve, then QR, then content stays as it is (1 hour). The rebuild stops modify from touching an empty reservation.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-107")]
    public async Task RULE_107_ReservedLinkExpiresAfterOneHour()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var now = app.Time.GetUtcNow();

        using var reserve = await caller.SendAsync(HttpMethod.Post, "/api/files/reserve");
        var id = (await reserve.JsonAsync()).GetProperty("FileInfo").GetProperty("Id").GetString()!;
        var link = await app.LinkAsync(id);
        using var qr = await caller.SendAsync(HttpMethod.Get, $"/api/files/qr/{id}");
        app.Time.Advance(TimeSpan.FromMinutes(61));
        await RunCleanupAsync(app);

        Assert.AreEqual(15, id.Length);
        Assert.AreEqual(LinkState.Reserved, link.State);
        Assert.IsNull(link.ContentId);
        Assert.AreEqual(caller.UserId, link.OwnerId);
        Assert.AreEqual(now.AddHours(1), link.ReservedUntil);
        Assert.AreEqual("image/png", qr.Content.Headers.ContentType?.MediaType, "the QR code exists before the document");
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.LinkId == id && e.Action == "Reserve")));
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == id)), "an unfilled reservation is deleted after 1 hour");
    }

    /// <summary>RULE-110 Hourly clean-up schedule and steps (legacy: internal/storage/FileServing.go:733-767).</summary>
    /// <remarks>
    /// Given: Qhub starts at 08:00 (cmd/qhub/Main.go:60)<br/>
    /// When: the clean-up runs<br/>
    /// Then: , in order: download markers older than 24 h are dropped; expired, exhausted and due-pending rows are processed; temp files older than 24 h are removed; API keys whose owner no longer exists are removed; expired sessions and expired API keys are purged; and (scheduled runs only) logs older than the retention period are purged. The next run starts 1 h after this one ends. Then
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-110")]
    public async Task RULE_110_CleanupRunsAtStartThenOneHourAfterEachRun()
    {
        var settings = QhubFactory.ValidSettings(await SqlServer.NewDatabaseAsync());
        string beforeStart;
        await using (var seeding = new QhubFactory(settings))
            beforeStart = (await seeding.SeedLinkAsync(downloads: 0)).Id;

        await using var app = new QhubFactory(settings, cleanupWorker: true);
        app.CreateClient().Dispose();
        var ranAtStart = await EventuallyAsync(() => app.InDbAsync(db => db.Links.AllAsync(l => l.Id != beforeStart)));
        var later = (await app.SeedLinkAsync(downloads: 0)).Id;
        // shortcut: real-time settle so the start-up run reaches its hourly Task.Delay before fake time moves; FakeTimeProvider exposes no timer count.
        await Task.Delay(TimeSpan.FromSeconds(3));
        app.Time.Advance(TimeSpan.FromMinutes(59));
        var notYet = !await EventuallyAsync(() => app.InDbAsync(db => db.Links.AllAsync(l => l.Id != later)), TimeSpan.FromSeconds(3));
        app.Time.Advance(TimeSpan.FromMinutes(1));
        var ranAfterAnHour = await EventuallyAsync(() => app.InDbAsync(db => db.Links.AllAsync(l => l.Id != later)));

        Assert.IsTrue(ranAtStart, "the clean-up runs at start");
        Assert.IsTrue(notYet, "not before an hour has passed");
        Assert.IsTrue(ranAfterAnHour, "and again one hour after the previous run");
    }

    /// <summary>RULE-111 Delete content only when no other row shares its hash, and retry if storage fails (legacy: internal/storage/FileServing.go:847-868).</summary>
    /// <remarks>
    /// Given: expired rows A and B both with hash H, and live row C with hash K S3 does not answer when the content of an expired row D is deleted → D's row stays and is retried next hour<br/>
    /// When: the clean-up processes A → B shares H, so only A's row is deleted it processes B → no row shares H, so the content H is deleted, then B's row<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// <br/>Reviewer: Correct. The orphaned-content case is fixed in RULE-106.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-111")]
    public async Task RULE_111_ContentIsDeletedOnlyWhenUnsharedAndRetriedOnFailure()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var shared = Api.Pdf(tag: "111");
        var expired = Id(await caller.AddAsync(shared, ("expiryMinutes", "1")));
        var live = Id(await caller.AddAsync(shared));
        var lone = Id(await caller.AddAsync(Api.Pdf(tag: "111-lone")));
        var loneContent = await app.InDbAsync(db => db.StoredContents.AsNoTracking().SingleAsync(c => c.Id == db.Links.Single(l => l.Id == lone).ContentId));
        var blob = Path.Combine(app.Services.GetRequiredService<IOptions<QhubOptions>>().Value.DataDir, loneContent.Location);

        app.Time.Advance(TimeSpan.FromMinutes(2));
        await RunCleanupAsync(app);
        using (new FileStream(blob, FileMode.Open, FileAccess.Read, FileShare.None)) // the storage refuses the delete
            await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", lone));
        var leftBehind = File.Exists(blob);
        await RunCleanupAsync(app);

        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == expired)));
        Assert.IsNotNull((await app.LinkAsync(live)).ContentId, "shared content stays with the live link");
        Assert.IsTrue(leftBehind, "a failed storage delete leaves the blob");
        Assert.IsFalse(File.Exists(blob), "the next clean-up retries and removes it");
    }

    /// <summary>RULE-112 Immediate deletion (legacy: internal/storage/FileServing.go:870-890).</summary>
    /// <remarks>
    /// Given: live link L with a download in progress<br/>
    /// When: the owner calls /files/delete?id=L with no delay<br/>
    /// Then: L's ExpireAt = 0, its download-in-progress markers are cleared, a "deleted by" audit entry is written (Api.go:366), and a background clean-up deletes the row and the content (if no other row has the same hash)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-112")]
    public async Task RULE_112_ImmediateDeletion()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var id = Id(await caller.AddAsync(Api.Pdf(tag: "112")));
        var content = (await app.LinkAsync(id)).ContentId!.Value;

        using var delete = await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", id));

        Assert.AreEqual(HttpStatusCode.OK, delete.StatusCode);
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == id)));
        Assert.IsFalse(await app.InDbAsync(db => db.StoredContents.AnyAsync(c => c.Id == content)), "unshared content goes too");
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.LinkId == id && e.Action == "Delete" && e.ActorUserId == caller.UserId)));
    }

    /// <summary>RULE-113 Scheduled (delayed) deletion (legacy: internal/storage/FileServing.go:904-931).</summary>
    /// <remarks>
    /// Given: live link L<br/>
    /// When: /files/delete is called with delay = 600 at 10:00:00<br/>
    /// Then: PendingDeletion = 10:10:00, L is hidden from customers immediately, the admin list shows it as pending, and the audit log says "deleted by" now And at 10:10:00, if PendingDeletion is still 10:10:00, L is deleted as in the immediate-deletion card if Qhub restarts before then, the hourly clean-up deletes L once PendingDeletion &lt; now
    /// <br/>Reviewer: The behaviour is right. The rebuild rejects a negative delay and logs the actual deletion when it runs.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-113")]
    public async Task RULE_113_ScheduledDeletion()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        using var browser = app.Browser();
        var id = Id(await caller.AddAsync(Api.Pdf(tag: "113")));
        var now = app.Time.GetUtcNow();

        await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", id), ("delay", "600"));
        var pending = await app.LinkAsync(id);
        var customer = await browser.GetAsync($"/d?id={id}");
        using var list = await caller.SendAsync(HttpMethod.Get, "/api/files/list");
        var listed = (await list.JsonAsync()).EnumerateArray().Single(f => f.GetProperty("Id").GetString() == id);
        app.Time.Advance(TimeSpan.FromSeconds(600));
        await RunCleanupAsync(app);

        Assert.AreEqual(LinkState.PendingDeletion, pending.State);
        Assert.AreEqual(now.AddSeconds(600), pending.DeleteAt);
        Portal.AssertRedirect(customer, "./error");
        Assert.IsTrue(listed.GetProperty("IsPendingDeletion").GetBoolean());
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == id)));
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.LinkId == id && e.Action == "Deleted")), "the actual deletion is logged when it runs");
    }

    /// <summary>RULE-122 Filling a reserved link with its document (legacy: internal/webserver/api/Api.go:689-715).</summary>
    /// <remarks>
    /// Given: reserved link R owned by user 7, reserved 20 minutes ago<br/>
    /// When: user 7 uploads to /files/content?id=R with password "4821" and expiryDays 14 user 7 uploads to R a second time → 409 "The link already has a document" user 8 uploads to R → 401 the reservation has expired or is pending deletion → 404<br/>
    /// Then: R gets the content, the hash, a new UploadDate = now, ExpireAt = now+14d and DownloadsRemaining = 1 (FileServing.go:301 reuses the reserved ID)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-122")]
    public async Task RULE_122_FillingAReservedLink()
    {
        var app = await Portal.AppAsync();
        using var owner = await app.NewCallerAsync();
        using var other = await app.NewCallerAsync();
        var r = await ReserveAsync(owner);
        var stale = await ReserveAsync(owner);
        app.Time.Advance(TimeSpan.FromMinutes(20));
        var now = app.Time.GetUtcNow();

        using var fill = await FillAsync(owner, r, ("password", "4821"), ("expiryDays", "14"));
        using var again = await FillAsync(owner, r, ("password", "4821"));
        using var notOwner = await FillAsync(other, await ReserveAsync(owner), ("password", "4821"));
        app.Time.Advance(TimeSpan.FromMinutes(41));
        using var expired = await FillAsync(owner, stale, ("password", "4821"));

        var info = (await fill.JsonAsync()).GetProperty("FileInfo");
        Assert.AreEqual(r, info.GetProperty("Id").GetString(), "the reserved ID is kept");
        Assert.AreEqual(1, info.GetProperty("DownloadsRemaining").GetInt32());
        Assert.AreEqual(now.AddDays(14).ToUnixTimeSeconds(), info.GetProperty("ExpireAt").GetInt64());
        Assert.AreEqual(now.ToUnixTimeSeconds(), info.GetProperty("UploadDate").GetInt64());
        Api.AssertError(again, HttpStatusCode.Conflict, 0, await again.JsonAsync(), "The link already has a document");
        Api.AssertError(notOwner, HttpStatusCode.Unauthorized, 6, await notOwner.JsonAsync());
        Api.AssertError(expired, HttpStatusCode.NotFound, 5, await expired.JsonAsync());
    }

    /// <summary>RULE-127 Defaults and validation when a link is created from a whole-file upload (/files/add, /files/content) (legacy: internal/webserver/fileupload/FileUpload.go:120-159).</summary>
    /// <remarks>
    /// Given: a form with no allowedDownloads, no expiryDays, password "4821" expiryMinutes = 30 password = "" → the upload is refused ("password is required")<br/>
    /// When: the upload completes<br/>
    /// Then: DownloadsRemaining = 1 and ExpireAt = now + 14×24h, both limited, and the code is stored as an Argon2id hash ExpireAt = now + 30 min and UnlimitedTime = false, even if isUnlimitedTime = true was sent
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-127")]
    public async Task RULE_127_WholeFileUploadDefaultsAndValidation()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        using var browser = app.Browser();
        var now = app.Time.GetUtcNow();

        using var filled = await FillAsync(caller, await ReserveAsync(caller), ("password", "4821"));
        var defaults = (await filled.JsonAsync()).GetProperty("FileInfo");
        using var emptyCode = await caller.Client.PostAsync("/api/files/add", Api.Upload(Api.Pdf(), fields: [("password", "")]));
        var minutes = await caller.AddAsync(Api.Pdf(), ("expiryMinutes", "30"), ("isUnlimitedTime", "true"));
        var opened = await browser.PostCodeAsync(Id(minutes), "4821");

        Assert.AreEqual(1, defaults.GetProperty("DownloadsRemaining").GetInt32(), "the same defaults on /files/content");
        Assert.AreEqual(now.AddDays(14).ToUnixTimeSeconds(), defaults.GetProperty("ExpireAt").GetInt64());
        Api.AssertError(emptyCode, HttpStatusCode.BadRequest, 0, await emptyCode.JsonAsync(), "password is required");
        Assert.AreEqual(now.AddMinutes(30).ToUnixTimeSeconds(), minutes.GetProperty("ExpireAt").GetInt64());
        Assert.IsFalse(minutes.GetProperty("UnlimitedTime").GetBoolean());
        Assert.AreEqual(HttpStatusCode.SeeOther, opened.StatusCode, "the customer opens it with the code");
    }

    /// <summary>RULE-145 Which uploads are encrypted depends on the encryption mode (legacy: internal/storage/FileServing.go:476-488).</summary>
    /// <remarks>
    /// Given: QHUB_ENCRYPTION=local and an S3 bucket configured QHUB_ENCRYPTION=full<br/>
    /// When: a document is uploaded<br/>
    /// Then: it is stored unencrypted in S3 it is encrypted (AES-GCM, one key per file wrapped by the master key)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-145")]
    public async Task RULE_145_EncryptionModeDecidesWhichUploadsAreEncrypted()
    {
        var fixture = await Encrypted.Value;
        await using var app = new QhubFactory(fixture.Settings());
        using var caller = await app.NewCallerAsync(UserPermissions.List);

        var content = await app.InDbAsync(db => db.StoredContents.AsNoTracking().SingleAsync(c => c.Id == db.Links.Single(l => l.Id == fixture.LinkId).ContentId));
        var onDisk = await File.ReadAllBytesAsync(Path.Combine(fixture.DataDir, content.Location));
        using var range = new HttpRequestMessage(HttpMethod.Get, $"/api/files/download/{fixture.LinkId}");
        range.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(70_000, 70_009);
        using var partial = await caller.Client.SendAsync(range);
        var s3 = fixture.Settings();
        (s3["QHUB_AWS_BUCKET"], s3["QHUB_AWS_REGION"], s3["QHUB_AWS_KEY"], s3["QHUB_AWS_KEY_SECRET"]) = ("bucket", "us-east-1", "fake-key", "fake-secret");

        Assert.IsTrue(content.Encrypted);
        Assert.HasCount(60, content.WrappedKey!, "a per-file key wrapped by the master key");
        Assert.AreEqual(Qhub.Features.Storage.ContentEncryption.CipherLength(fixture.Bytes.Length), onDisk.Length);
        Assert.IsFalse(onDisk.AsSpan().IndexOf(fixture.Bytes.AsSpan(1000, 64)) >= 0, "the plaintext is not on disk");
        Assert.AreEqual(HttpStatusCode.PartialContent, partial.StatusCode, "Range works on encrypted content");
        CollectionAssert.AreEqual(fixture.Bytes[70_000..70_010], await partial.Content.ReadAsByteArrayAsync());
        Assert.Contains("with QHUB_AWS_BUCKET use the bucket's server-side encryption", StartFails(s3).ToString(), "S3 content relies on bucket-side encryption");
    }

    /// <summary>RULE-006 (corrected) The dedup key is HMAC-SHA-256 with a server secret, not SHA-1. Whether cross-user dedup stays is Q3 (legacy: internal/storage/FileServing.go:424-474).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/storage/FileServing.go:424-474, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: The dedup key is HMAC-SHA-256 with a server secret, not SHA-1. Whether cross-user dedup stays is Q3
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-006")]
    public async Task RULE_006_DedupKeyIsHmacWithServerKey()
    {
        var app = await Portal.AppAsync();
        using var one = await app.NewCallerAsync();
        using var two = await app.NewCallerAsync();
        var bytes = Api.Pdf(tag: "006");

        var a = await app.LinkAsync(Id(await one.AddAsync(bytes)));
        var b = await app.LinkAsync(Id(await one.AddAsync(bytes)));
        var c = await app.LinkAsync(Id(await two.AddAsync(bytes)));
        var key = await app.InDbAsync(db => db.StoredContents.Where(x => x.Id == a.ContentId).Select(x => x.DedupKey).SingleAsync());

        Assert.AreEqual(a.ContentId, b.ContentId, "the same owner's identical upload is stored once");
        Assert.AreNotEqual(a.ContentId, c.ContentId, "another owner's is not (brief Q3: within one owner)");
        Assert.HasCount(32, key!);
        CollectionAssert.AreNotEqual(SHA256.HashData(bytes), key, "not a plain hash of the content");
    }

    /// <summary>RULE-014 (corrected) Chunked upload settings and RULE-124 chunked defaults: one validator for every upload path, rejecting negatives, with the defaults in one place (legacy: internal/webserver/api/routing.go:582-632).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/api/routing.go:582-632, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Chunked upload settings and RULE-124 chunked defaults: one validator for every upload path, rejecting negatives, with the defaults in one place
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-014")]
    public async Task RULE_014_OneValidatorForEveryUploadPathRejectsNegatives()
    {
        // The admin page's /uploadChunk path is proven with Phase 3.
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var bytes = Api.Pdf(2000);
        await AddChunkAsync(caller, "neg014", 0, bytes);

        using var add = await caller.Client.PostAsync("/api/files/add", Api.Upload(Api.Pdf(), fields: [("password", "4821"), ("allowedDownloads", "-1")]));
        using var content = await FillAsync(caller, await ReserveAsync(caller), ("password", "4821"), ("expiryDays", "-1"));
        using var chunk = await CompleteAsync(caller, "neg014", bytes.Length, ("allowedDownloads", "-1"));
        using var notANumber = await caller.Client.PostAsync("/api/files/add", Api.Upload(Api.Pdf(), fields: [("password", "4821"), ("expiryDays", "soon")]));

        foreach (var refused in new[] { add, content, chunk, notANumber })
            Assert.AreEqual(HttpStatusCode.BadRequest, refused.StatusCode, (await refused.JsonAsync()).ToString());
    }

    /// <summary>RULE-048 (corrected) A code can be changed but must be non-empty and valid; it can't be removed (legacy: internal/webserver/api/Api.go:136-145).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/api/Api.go:136-145, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: A code can be changed but must be non-empty and valid; it can't be removed
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-048")]
    public async Task RULE_048_AccessCodeCanBeChangedButNotRemoved()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        using var browser = app.Browser();
        var id = Id(await caller.AddAsync(Api.Pdf(), ("allowedDownloads", "5")));

        // TestHost drops headers whose value is "" (Kestrel keeps them); a blank value takes the same path to the validator.
        using var removed = await caller.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", id), ("password", " "));
        using var changed = await caller.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", id), ("password", "7777"));
        var oldCode = await browser.PostCodeAsync(id, "4821");
        var newCode = await browser.PostCodeAsync(id, "7777");

        Api.AssertError(removed, HttpStatusCode.BadRequest, 4, await removed.JsonAsync(), "can be changed, but not removed");
        Assert.AreEqual(HttpStatusCode.OK, changed.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, oldCode.StatusCode, "the old code no longer opens it");
        Assert.AreEqual(HttpStatusCode.SeeOther, newCode.StatusCode);
    }

    /// <summary>RULE-052 (corrected) Every document needs a customer code on every upload path, the admin page included (see Q6) (legacy: internal/webserver/api/Api.go:425-452).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/api/Api.go:425-452, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Every document needs a customer code on every upload path, the admin page included (see Q6)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-052")]
    public async Task RULE_052_EveryUploadPathRequiresAnAccessCode()
    {
        // The admin page's /uploadChunk path is proven with Phase 3.
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var bytes = Api.Pdf(2000);
        await AddChunkAsync(caller, "nocode052", 0, bytes);
        var reserved = await ReserveAsync(caller);

        using var add = await caller.Client.PostAsync("/api/files/add", Api.Upload(Api.Pdf()));
        using var content = await FillAsync(caller, reserved);
        using var chunk = await CompleteAsync(caller, "nocode052", bytes.Length, withCode: false);

        foreach (var refused in new[] { add, content, chunk })
            Assert.Contains("password is required", (await refused.JsonAsync()).GetProperty("ErrorMessage").GetString()!);
        Assert.AreEqual(LinkState.Reserved, (await app.LinkAsync(reserved)).State, "the reservation stays empty");
    }

    /// <summary>RULE-062 (corrected) A duplicate keeps the original's code or takes a new valid one; a code-free copy is not allowed (legacy: internal/webserver/api/routing.go:346-369).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/api/routing.go:346-369, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: A duplicate keeps the original's code or takes a new valid one; a code-free copy is not allowed
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-062")]
    public async Task RULE_062_DuplicateKeepsOrReplacesCodeNeverDropsIt()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        using var browser = app.Browser();
        var id = Id(await caller.AddAsync(Api.Pdf()));

        using var kept = await caller.SendAsync(HttpMethod.Post, "/api/files/duplicate", ("id", id), ("originalPassword", "true"));
        using var replaced = await caller.SendAsync(HttpMethod.Post, "/api/files/duplicate", ("id", id), ("password", "5555"));
        // TestHost drops headers whose value is "" (Kestrel keeps them); a blank value takes the same path to the validator.
        using var dropped = await caller.SendAsync(HttpMethod.Post, "/api/files/duplicate", ("id", id), ("password", " "));
        var keptId = (await kept.JsonAsync()).GetProperty("Id").GetString()!;
        var replacedId = (await replaced.JsonAsync()).GetProperty("Id").GetString()!;

        Assert.AreEqual(HttpStatusCode.SeeOther, (await browser.PostCodeAsync(keptId, "4821")).StatusCode, "the copy keeps the original code");
        Assert.AreEqual(HttpStatusCode.SeeOther, (await browser.PostCodeAsync(replacedId, "5555")).StatusCode, "or takes the new one");
        Api.AssertError(dropped, HttpStatusCode.BadRequest, 4, await dropped.JsonAsync(), "can be changed, but not removed");
        Assert.AreEqual((await app.LinkAsync(id)).ContentId, (await app.LinkAsync(keptId)).ContentId);
    }

    /// <summary>RULE-106 (corrected) Replace keeps the link and code, deletes the old content when unshared, revokes issued passes, and doesn't reset the lock (legacy: internal/storage/FileServing.go:361-385).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/storage/FileServing.go:361-385, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Replace keeps the link and code, deletes the old content when unshared, revokes issued passes, and doesn't reset the lock
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-106")]
    public async Task RULE_106_ReplaceKeepsLinkAndCodeAndRevokesPasses()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync(UserPermissions.Replace);
        using var browser = app.Browser();
        var target = Id(await caller.AddAsync(Api.Pdf(), ("allowedDownloads", "5")));
        var newBytes = Api.Pdf(tag: "106-new");
        var source = Id(await caller.AddAsync(newBytes));
        var oldContent = (await app.LinkAsync(target)).ContentId!.Value;
        await browser.PostCodeAsync(target, "4821");
        using (var locker = app.Browser())
            for (var i = 0; i < 2; i++) await locker.PostCodeAsync(target, "1111");

        using var replace = await caller.SendAsync(HttpMethod.Put, "/api/files/replace", ("id", target), ("idNewContent", source), ("deleteNewFile", "true"));
        var revoked = await browser.GetAsync($"/downloadFile?id={target}");
        var reopened = await browser.PostCodeAsync(target, "4821");
        var download = await browser.GetAsync($"/downloadFile?id={target}");

        Assert.AreEqual(HttpStatusCode.OK, replace.StatusCode, (await replace.JsonAsync()).ToString());
        Portal.AssertRedirect(revoked, $"./d?id={target}");
        Assert.AreEqual(HttpStatusCode.SeeOther, reopened.StatusCode, "the same link and code");
        CollectionAssert.AreEqual(newBytes, await download.Content.ReadAsByteArrayAsync(), "now serving the new content");
        Assert.IsFalse(await app.InDbAsync(db => db.StoredContents.AnyAsync(c => c.Id == oldContent)), "unshared old content deleted");
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == source)), "deleteNewFile removes the source link");
    }

    [TestMethod]
    [TestCategory("RULE-106")]
    public async Task RULE_106_ReplaceDoesNotResetTheLock()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync(UserPermissions.Replace);
        var target = Id(await caller.AddAsync(Api.Pdf()));
        var source = Id(await caller.AddAsync(Api.Pdf()));
        using (var locker = app.Browser())
            for (var i = 0; i < 5; i++) await locker.PostCodeAsync(target, "1111");

        await caller.SendAsync(HttpMethod.Put, "/api/files/replace", ("id", target), ("idNewContent", source));

        Assert.AreEqual(5, (await app.InDbAsync(db => db.CodeLocks.AsNoTracking().SingleAsync(c => c.LinkId == target))).FailedAttempts);
    }

    /// <summary>RULE-114 (corrected) Restore works only on a pending link within its delay; otherwise it returns a clear error (legacy: internal/storage/FileServing.go:933-946).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/storage/FileServing.go:933-946, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Restore works only on a pending link within its delay; otherwise it returns a clear error
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-114")]
    public async Task RULE_114_RestoreOnlyWorksOnPendingLinkWithinDelay()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var live = Id(await caller.AddAsync(Api.Pdf()));
        var within = Id(await caller.AddAsync(Api.Pdf()));
        var late = Id(await caller.AddAsync(Api.Pdf()));
        await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", late), ("delay", "10"));
        app.Time.Advance(TimeSpan.FromSeconds(11));
        await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", within), ("delay", "600"));

        using var notPending = await caller.SendAsync(HttpMethod.Post, "/api/files/restore", ("id", live));
        using var tooLate = await caller.SendAsync(HttpMethod.Post, "/api/files/restore", ("id", late));
        using var restored = await caller.SendAsync(HttpMethod.Post, "/api/files/restore", ("id", within));

        Api.AssertError(notPending, HttpStatusCode.BadRequest, 10, await notPending.JsonAsync(), "not scheduled for deletion");
        Api.AssertError(tooLate, HttpStatusCode.NotFound, 5, await tooLate.JsonAsync());
        Assert.AreEqual(HttpStatusCode.OK, restored.StatusCode);
        Assert.AreEqual(LinkState.Live, (await app.LinkAsync(within)).State);
    }

    /// <summary>RULE-115 (corrected) A chunk ledger refuses completion while any chunk is missing (legacy: internal/storage/chunking/Chunking.go:206-260).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/storage/chunking/Chunking.go:206-260, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: A chunk ledger refuses completion while any chunk is missing
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-115")]
    public async Task RULE_115_ChunkedUploadCompletesOnlyWithFullCoverage()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        const int mb = 1024 * 1024;
        var bytes = Api.Pdf(2 * mb + mb / 2, "115");
        await AddChunkAsync(caller, "gap115", 0, bytes[..mb], bytes.Length);
        await AddChunkAsync(caller, "gap115", 2 * mb, bytes[(2 * mb)..], bytes.Length);
        foreach (var offset in new[] { 0, mb, 2 * mb })
            await AddChunkAsync(caller, "full115", offset, bytes[offset..Math.Min(offset + mb, bytes.Length)], bytes.Length);

        using var gap = await CompleteAsync(caller, "gap115", bytes.Length);
        using var full = await CompleteAsync(caller, "full115", bytes.Length);
        var id = (await full.JsonAsync()).GetProperty("FileInfo").GetProperty("Id").GetString()!;
        using var download = await caller.SendAsync(HttpMethod.Get, $"/api/files/download/{id}");

        Api.AssertError(gap, HttpStatusCode.BadRequest, 0, await gap.JsonAsync(), "upload incomplete");
        CollectionAssert.AreEqual(bytes, await download.Content.ReadAsByteArrayAsync(), "a complete upload round-trips byte-identical");
    }

    /// <summary>RULE-115 with encryption on: a complete chunked upload is stored encrypted and still round-trips byte-identical.</summary>
    [TestMethod]
    [TestCategory("RULE-115")]
    public async Task RULE_115_ChunkedUploadRoundTripsWithEncryptionOn()
    {
        var fixture = await Encrypted.Value;
        await using var app = new QhubFactory(fixture.Settings());
        using var caller = await app.NewCallerAsync();
        const int mb = 1024 * 1024;
        var bytes = Api.Pdf(mb + mb / 2, "115-enc");
        foreach (var offset in new[] { 0, mb })
            await AddChunkAsync(caller, "enc115", offset, bytes[offset..Math.Min(offset + mb, bytes.Length)], bytes.Length);

        using var full = await CompleteAsync(caller, "enc115", bytes.Length);
        var info = (await full.JsonAsync()).GetProperty("FileInfo");
        using var download = await caller.SendAsync(HttpMethod.Get, $"/api/files/download/{info.GetProperty("Id").GetString()}");

        Assert.IsTrue(info.GetProperty("IsEncrypted").GetBoolean());
        CollectionAssert.AreEqual(bytes, await download.Content.ReadAsByteArrayAsync());
    }

    /// <summary>RULE-120 (corrected) Edit applies only to live links with validated values; whether a new code lifts the lock follows RULE-012 (legacy: internal/webserver/api/Api.go:102-145).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/api/Api.go:102-145, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Edit applies only to live links with validated values; whether a new code lifts the lock follows RULE-012
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-120")]
    public async Task RULE_120_EditAppliesOnlyToLiveLinksWithValidValues()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var live = Id(await caller.AddAsync(Api.Pdf()));
        var reserved = await ReserveAsync(caller);
        var pending = Id(await caller.AddAsync(Api.Pdf()));
        await caller.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", pending), ("delay", "600"));
        using (var locker = app.Browser())
            for (var i = 0; i < 5; i++) await locker.PostCodeAsync(live, "1111");

        using var onReserved = await caller.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", reserved), ("allowedDownloads", "3"));
        using var onPending = await caller.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", pending), ("allowedDownloads", "3"));
        using var negative = await caller.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", live), ("allowedDownloads", "-1"));
        using var badCode = await caller.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", live), ("password", "12"));
        using var ok = await caller.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", live), ("allowedDownloads", "3"), ("password", "2468"));

        Api.AssertError(onReserved, HttpStatusCode.NotFound, 5, await onReserved.JsonAsync());
        Api.AssertError(onPending, HttpStatusCode.NotFound, 5, await onPending.JsonAsync());
        Assert.AreEqual(HttpStatusCode.BadRequest, negative.StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, badCode.StatusCode);
        Assert.AreEqual(3, (await ok.JsonAsync()).GetProperty("DownloadsRemaining").GetInt32());
        Assert.IsFalse(await app.InDbAsync(db => db.CodeLocks.AnyAsync(c => c.LinkId == live)), "a new code lifts the lock (RULE-012)");
    }

    /// <summary>RULE-124 (corrected) Chunked upload settings and RULE-124 chunked defaults: one validator for every upload path, rejecting negatives, with the defaults in one place (legacy: internal/webserver/api/routing.go:598-632).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/api/routing.go:598-632, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Chunked upload settings and RULE-124 chunked defaults: one validator for every upload path, rejecting negatives, with the defaults in one place
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-124")]
    public async Task RULE_124_ChunkedUploadDefaultsLiveInOnePlace()
    {
        var app = await Portal.AppAsync();
        using var caller = await app.NewCallerAsync();
        var now = app.Time.GetUtcNow();
        var bytes = Api.Pdf(5000);
        await AddChunkAsync(caller, "defaults124", 0, bytes);

        using var chunked = await CompleteAsync(caller, "defaults124", bytes.Length);
        var info = (await chunked.JsonAsync()).GetProperty("FileInfo");
        var whole = await caller.AddAsync(Api.Pdf());

        Assert.AreEqual(UploadParameters.DefaultDownloads, info.GetProperty("DownloadsRemaining").GetInt32());
        Assert.AreEqual(now.AddDays(UploadParameters.DefaultExpiryDays).ToUnixTimeSeconds(), info.GetProperty("ExpireAt").GetInt64());
        Assert.AreEqual(whole.GetProperty("DownloadsRemaining").GetInt32(), info.GetProperty("DownloadsRemaining").GetInt32(), "the same defaults as /files/add");
        Assert.AreEqual(whole.GetProperty("ExpireAt").GetInt64(), info.GetProperty("ExpireAt").GetInt64());
    }

    static string Id(JsonElement fileInfo) => fileInfo.GetProperty("Id").GetString()!;

    static List<string> Blobs(QhubFactory app)
    {
        var dir = Path.Combine(app.Services.GetRequiredService<IOptions<QhubOptions>>().Value.DataDir, "content");
        return Directory.Exists(dir) ? [.. Directory.GetFiles(dir)] : [];
    }

    static async Task RunCleanupAsync(QhubFactory app)
    {
        using var scope = app.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<Cleanup>().RunAsync(scheduled: true, CancellationToken.None);
    }

    static async Task<bool> EventuallyAsync(Func<Task<bool>> condition, TimeSpan? within = null)
    {
        var deadline = DateTime.UtcNow + (within ?? TimeSpan.FromSeconds(30));
        while (DateTime.UtcNow < deadline)
        {
            if (await condition()) return true;
            await Task.Delay(200);
        }
        return await condition();
    }

    static async Task<string> ReserveAsync(Api.Caller caller)
    {
        using var response = await caller.SendAsync(HttpMethod.Post, "/api/files/reserve");
        return (await response.JsonAsync()).GetProperty("FileInfo").GetProperty("Id").GetString()!;
    }

    static async Task<HttpResponseMessage> FillAsync(Api.Caller caller, string id, params (string Name, string Value)[] fields)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/files/content") { Content = Api.Upload(Api.Pdf(), fields: fields) };
        request.Headers.Add("id", id);
        return await caller.Client.SendAsync(request);
    }

    static async Task AddChunkAsync(Api.Caller caller, string uuid, long offset, byte[] chunk, long? total = null)
    {
        var form = new MultipartFormDataContent
        {
            { new ByteArrayContent(chunk), "file", "blob" },
            { new StringContent(uuid), "uuid" },
            { new StringContent(offset.ToString(System.Globalization.CultureInfo.InvariantCulture)), "offset" },
            { new StringContent((total ?? chunk.Length).ToString(System.Globalization.CultureInfo.InvariantCulture)), "filesize" },
        };
        using var response = await caller.Client.PostAsync("/api/chunk/add", form);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, (await response.JsonAsync()).ToString());
    }

    static Task<HttpResponseMessage> CompleteAsync(Api.Caller caller, string uuid, long size, params (string Name, string Value)[] extra) =>
        CompleteAsync(caller, uuid, size, true, extra);

    static Task<HttpResponseMessage> CompleteAsync(Api.Caller caller, string uuid, long size, bool withCode, params (string Name, string Value)[] extra)
    {
        var headers = new List<(string, string)> { ("uuid", uuid), ("filename", "base64:" + Convert.ToBase64String("كشف.pdf"u8.ToArray())), ("filesize", size.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("contenttype", "application/pdf") };
        if (withCode) headers.Add(("password", "4821"));
        headers.AddRange(extra);
        return caller.SendAsync(HttpMethod.Post, "/api/chunk/complete", [.. headers]);
    }

    static Exception StartFails(Dictionary<string, string?> settings)
    {
        using var app = new QhubFactory(settings);
        return Assert.Throws<Exception>(() => app.CreateClient());
    }

    /// <summary>One database with encryption on, a password, and one encrypted 200 KB upload, shared by the encryption tests.</summary>
    sealed record EncryptedFixture(string Db, string DataDir, string ServerKey, string LinkId, byte[] Bytes)
    {
        public const string Password = "fake-encryption-password-1234";

        public Dictionary<string, string?> Settings(string encryption = "on", string password = Password)
        {
            var settings = QhubFactory.ValidSettings(Db);
            settings["QHUB_DATA_DIR"] = DataDir;
            settings["QHUB_SERVER_KEY"] = ServerKey;
            settings["QHUB_ENCRYPTION"] = encryption;
            settings["QHUB_ENCRYPTION_PASSWORD"] = password;
            return settings;
        }
    }

    static readonly Lazy<Task<EncryptedFixture>> Encrypted = new(async () =>
    {
        var settings = QhubFactory.ValidSettings(await SqlServer.NewDatabaseAsync());
        var fixture = new EncryptedFixture(settings["QHUB_DB_CONNECTION"]!, settings["QHUB_DATA_DIR"]!, settings["QHUB_SERVER_KEY"]!, "", Api.Pdf(200_000, "encrypted"));
        await using var app = new QhubFactory(fixture.Settings());
        using var caller = await app.NewCallerAsync();
        return fixture with { LinkId = Id(await caller.AddAsync(fixture.Bytes)) };
    });
}
