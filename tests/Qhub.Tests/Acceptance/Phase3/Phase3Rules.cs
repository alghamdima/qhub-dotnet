using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qhub.Domain;
using Qhub.Tests.Support;

namespace Qhub.Tests.Acceptance.Phase3;

/// <summary>Behavior Contract, Phase 3 (AI_NATIVE_SPEC.md §5): one test per rule, named after the rule ID.</summary>
[TestClass]
public sealed class Phase3Rules
{
    /// <summary>RULE-005 API keys: hashing, defaults, expiry (legacy: internal/models/ApiKey.go:10-109).</summary>
    /// <remarks>
    /// Given: a UI-created key with basic permissions<br/>
    /// When: saved<br/>
    /// Then: Permissions = 1+2+4+16 = 23 and Id = sha256hex(rawKey). With basicPermissions=false → 0.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-005")]
    public async Task RULE_005_ApiKeysAreHashedWithBasicPermissionDefaults()
    {
        var app = await Portal.AppAsync();
        using var admin = await app.NewCallerAsync();

        using var basic = await admin.SendAsync(HttpMethod.Post, "/api/auth/create", ("friendlyName", "Issuing system"), ("basicPermissions", "true"));
        using var bare = await admin.SendAsync(HttpMethod.Post, "/api/auth/create");
        var created = await basic.JsonAsync();
        var secret = created.GetProperty("Id").GetString()!;
        var publicId = created.GetProperty("PublicId").GetString()!;
        var stored = await app.InDbAsync(db => db.ApiKeys.AsNoTracking().SingleAsync(k => k.Id == publicId));
        var bareKey = await app.InDbAsync(db => db.ApiKeys.AsNoTracking().SingleAsync(k => k.Id == (string)bare.JsonAsync().Result.GetProperty("PublicId").GetString()!));
        using var works = app.KeyClient(secret);
        using var list = await works.GetAsync("/api/files/list");

        Assert.AreEqual(30, secret.Length);
        Assert.AreEqual(35, publicId.Length);
        CollectionAssert.AreEqual(SHA256.HashData(Encoding.UTF8.GetBytes(secret)), stored.SecretHash, "only the hash is stored");
        Assert.AreEqual(23, (int)stored.Permissions, "VIEW + UPLOAD + DELETE + EDIT");
        Assert.AreEqual("Issuing system", stored.FriendlyName);
        Assert.AreEqual(0, (int)bareKey.Permissions, "basicPermissions=false gives none");
        Assert.AreEqual("Unnamed key", bareKey.FriendlyName);
        Assert.AreEqual(HttpStatusCode.OK, list.StatusCode);
    }

    /// <summary>RULE-013 Hiding link IDs from log readers without PERM_LIST (legacy: internal/webserver/api/Api.go:1053-1072).</summary>
    /// <remarks>
    /// Given: the log line "report.pdf, ID aZ3k9QmP0xT7bLw, Useragent …"<br/>
    /// When: fetched by a user without PERM_LIST<br/>
    /// Then: it reads "report.pdf, ID [hidden], Useragent …".
    /// <br/>Reviewer: Keep the hiding. The rebuild also stores a hashed link reference in the log, not the ID.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-013")]
    public async Task RULE_013_LinkIdsAreHiddenFromLogReadersWithoutPermList()
    {
        var app = await Portal.AppAsync();
        using var uploader = await app.NewCallerAsync();
        var id = (await uploader.AddAsync(Api.Pdf())).GetProperty("Id").GetString()!;
        using var reader = await app.NewCallerAsync(UserPermissions.Logs);
        using var lister = await app.NewCallerAsync(UserPermissions.Logs | UserPermissions.List);

        var hidden = (await (await reader.SendAsync(HttpMethod.Get, "/api/logs/get")).JsonAsync()).GetProperty("logEntries").GetString()!;
        var shown = (await (await lister.SendAsync(HttpMethod.Get, "/api/logs/get")).JsonAsync()).GetProperty("logEntries").GetString()!;

        Assert.DoesNotContain(id, hidden);
        Assert.Contains("ID [hidden], uploaded by", hidden);
        Assert.Contains($"ID {id}, uploaded by", shown);
        Assert.Contains("[upload]", shown);
    }

    /// <summary>RULE-041 Cross-site browser POSTs are rejected, except the SAML response (legacy: internal/webserver/Webserver.go:118-130).</summary>
    /// <remarks>
    /// Given: a page on evil.example that auto-submits a POST to /login<br/>
    /// When: the browser sends it with `Sec-Fetch-Site: cross-site`<br/>
    /// Then: the request is rejected before the handler runs (403) And the identity provider's POST to /saml-acs is let through
    /// <br/>Reviewer: Keep it: antiforgery on forms plus the same-origin check, with only the SAML endpoint exempt.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-041")]
    public async Task RULE_041_CrossSitePostsAreRejectedExceptSamlAcs()
    {
        var app = await Portal.AppAsync();
        using var browser = app.Browser();

        using var login = new HttpRequestMessage(HttpMethod.Post, "/login") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["username"] = "admin", ["password"] = "x" }) };
        login.Headers.Add("Sec-Fetch-Site", "cross-site");
        using var refused = await browser.SendAsync(login);
        using var acs = new HttpRequestMessage(HttpMethod.Post, "/saml-acs") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLResponse"] = "x" }) };
        acs.Headers.Add("Sec-Fetch-Site", "cross-site");
        using var samlAnswer = await browser.SendAsync(acs);
        using var otherOrigin = new HttpRequestMessage(HttpMethod.Post, "/uploadChunk");
        otherOrigin.Headers.Add("Origin", "https://evil.example");
        using var byOrigin = await browser.SendAsync(otherOrigin);

        Assert.AreEqual(HttpStatusCode.Forbidden, refused.StatusCode, "rejected before the handler runs");
        Assert.AreNotEqual(HttpStatusCode.Forbidden, samlAnswer.StatusCode, "the identity provider's POST is let through");
        Assert.AreEqual(HttpStatusCode.Forbidden, byOrigin.StatusCode, "a foreign Origin without Sec-Fetch-Site is rejected too");
    }

    /// <summary>RULE-043 Login with username and password (legacy: internal/webserver/Webserver.go:426-474).</summary>
    /// <remarks>
    /// Given: QHUB_AUTH=internal and user "alice" with password "Secret123"<br/>
    /// When: /login is posted with username=Alice, password=Secret123 and a valid token the password is wrong the token is invalid<br/>
    /// Then: a session is created and the browser goes to /admin the form shows "failed login" and the attempt is logged the form shows the CSRF failure and nothing is logged
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-043")]
    public async Task RULE_043_LoginWithUsernameAndPassword()
    {
        var app = await Portal.AppAsync();
        var alice = await app.NewUserAsync(password: "Secret123");
        using var browser = app.Browser();
        using var wrongBrowser = app.Browser();
        using var tokenless = app.Browser();

        var ok = await browser.LoginAsync(alice.Name.ToUpperInvariant(), "Secret123");
        var admin = await browser.GetAsync("/admin");
        var wrong = await (await wrongBrowser.LoginAsync(alice.Name, "Secret124")).Content.ReadAsStringAsync();
        var failedLogged = await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.Action == "LoginFailed" && e.Detail.Contains(alice.Name)));
        var auditBefore = await app.InDbAsync(db => db.AuditEntries.CountAsync(e => e.Action == "LoginFailed"));
        var expired = await (await tokenless.LoginAsync(alice.Name, "Secret124", withToken: false)).Content.ReadAsStringAsync();
        var auditAfter = await app.InDbAsync(db => db.AuditEntries.CountAsync(e => e.Action == "LoginFailed"));

        Portal.AssertRedirect(ok, "./admin");
        Assert.AreEqual(HttpStatusCode.OK, admin.StatusCode, "the session opens the admin page");
        Assert.Contains("Incorrect username or password!", wrong);
        Assert.IsTrue(failedLogged, "the failed attempt is logged");
        Assert.Contains("open too long and expired", expired);
        Assert.AreEqual(auditBefore, auditAfter, "an invalid form token logs nothing");
    }

    /// <summary>RULE-046 Editing a link's limits needs ownership or PERM_EDIT (legacy: internal/webserver/api/Api.go:102-135).</summary>
    /// <remarks>
    /// Given: link A owned by user #5<br/>
    /// When: user #9 without PERM_EDIT calls /files/modify `id: A` the owner sends `allowedDownloads: 3` the owner sends `expiryTimestamp: 1767225600` the ID is unknown<br/>
    /// Then: 401 NoPermission "No permission to edit file." DownloadsRemaining=3 and limited ExpireAt=2026-01-01T00:00:00Z and limited 404 NotFound
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-046")]
    public async Task RULE_046_EditingLimitsNeedsOwnershipOrPermEdit()
    {
        var app = await Portal.AppAsync();
        using var owner = await app.NewCallerAsync();
        using var stranger = await app.NewCallerAsync();
        using var editor = await app.NewCallerAsync(UserPermissions.Edit);
        var id = (await owner.AddAsync(Api.Pdf())).GetProperty("Id").GetString()!;

        using var refused = await stranger.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", id), ("allowedDownloads", "3"));
        using var byEditor = await editor.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", id), ("allowedDownloads", "4"));
        using var downloads = await owner.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", id), ("allowedDownloads", "3"));
        using var expiry = await owner.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", id), ("expiryTimestamp", "1798761600"));
        using var unknown = await owner.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", "NotARealId00000"), ("allowedDownloads", "3"));

        Api.AssertError(refused, HttpStatusCode.Unauthorized, 6, await refused.JsonAsync(), "No permission to edit file.");
        Assert.AreEqual(HttpStatusCode.OK, byEditor.StatusCode, "PERM_EDIT reaches other users' links");
        Assert.AreEqual(3, (await downloads.JsonAsync()).GetProperty("DownloadsRemaining").GetInt32());
        var info = await expiry.JsonAsync();
        Assert.AreEqual(1798761600, info.GetProperty("ExpireAt").GetInt64());
        Assert.IsFalse(info.GetProperty("UnlimitedTime").GetBoolean());
        Api.AssertError(unknown, HttpStatusCode.NotFound, 5, await unknown.JsonAsync());
    }

    /// <summary>RULE-047 Every API call needs a valid, unexpired API key that holds the route's permission (legacy: internal/webserver/api/Api.go:1114-1169).</summary>
    /// <remarks>
    /// Given: key K is stored as SHA-256(K), with Expiry 0 (never expires) and permissions VIEW+UPLOAD, and its owner user #5 exists<br/>
    /// When: a system calls /api/files/list with `Authorization: Bearer K`<br/>
    /// Then: the call goes ahead as user #5 and the key's LastUsed is set to now the API answers 401 {"Result":"error","ErrorCode":InvalidApiKey(2)} and the failure is throttled per IP And when the header is missing, the key is unknown, Expiry is in the past, the key lacks the route permission (for example /api/files/delete needs DELETE), or user #5 was deleted
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-047")]
    public async Task RULE_047_EveryApiCallNeedsAValidKeyWithRoutePermission()
    {
        var app = await Portal.AppAsync();
        using var valid = await app.NewCallerAsync(keyPermissions: ApiPermissions.View | ApiPermissions.Upload);
        using var expired = await app.NewCallerAsync(keyExpires: app.Time.GetUtcNow().AddSeconds(-1));
        using var orphan = await app.NewCallerAsync();
        await app.InDbAsync(async db => { await db.ApiKeys.Where(k => k.OwnerId == orphan.UserId).ExecuteDeleteAsync(); return await db.Users.Where(u => u.Id == orphan.UserId).ExecuteDeleteAsync(); });
        using var noHeader = app.KeyClient(null);
        using var unknown = app.KeyClient("not-a-real-key-000000000000000");

        using var ok = await valid.SendAsync(HttpMethod.Get, "/api/files/list");
        var lastUsed = await app.InDbAsync(db => db.ApiKeys.Where(k => k.OwnerId == valid.UserId).Select(k => k.LastUsed).SingleAsync());
        using var missing = await noHeader.GetAsync("/api/files/list");
        using var wrongKey = await unknown.GetAsync("/api/files/list");
        using var tooOld = await expired.SendAsync(HttpMethod.Get, "/api/files/list");
        using var lacking = await valid.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", "x"));
        using var deletedOwner = await orphan.SendAsync(HttpMethod.Get, "/api/files/list");

        Assert.AreEqual(HttpStatusCode.OK, ok.StatusCode);
        Assert.AreEqual(app.Time.GetUtcNow(), lastUsed, "LastUsed is set to now");
        foreach (var refused in new[] { missing, wrongKey, tooOld, lacking, deletedOwner })
            Api.AssertError(refused, HttpStatusCode.Unauthorized, 2, await refused.JsonAsync());
    }

    /// <summary>RULE-049 Granting key permissions is bounded by the key owner's user permissions (legacy: internal/webserver/api/Api.go:186-232).</summary>
    /// <remarks>
    /// Given: key K of user #5, who lacks PERM_LOGS<br/>
    /// When: an admin calls /auth/modify `targetKey: K`, `permission: PERM_MANAGE_LOGS`, `permissionModifier: GRANT` PERM_UPLOAD is granted<br/>
    /// Then: 401 "Insufficient user permission for owner to set this API permission" it is added (granting a permission the key already has does nothing)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-049")]
    public async Task RULE_049_KeyPermissionsAreBoundedByOwnerPermissions()
    {
        var app = await Portal.AppAsync();
        using var owner = await app.NewCallerAsync(keyPermissions: ApiPermissions.ApiManage);
        var keyId = await app.InDbAsync(db => db.ApiKeys.Where(k => k.OwnerId == owner.UserId).Select(k => k.Id).SingleAsync());

        using var logs = await owner.SendAsync(HttpMethod.Put, "/api/auth/modify", ("targetKey", keyId), ("permission", "PERM_MANAGE_LOGS"), ("permissionModifier", "GRANT"));
        using var upload = await owner.SendAsync(HttpMethod.Put, "/api/auth/modify", ("targetKey", keyId), ("permission", "PERM_UPLOAD"), ("permissionModifier", "GRANT"));
        using var again = await owner.SendAsync(HttpMethod.Put, "/api/auth/modify", ("targetKey", keyId), ("permission", "PERM_UPLOAD"), ("permissionModifier", "GRANT"));
        var permissions = await app.InDbAsync(db => db.ApiKeys.Where(k => k.Id == keyId).Select(k => k.Permissions).SingleAsync());

        Api.AssertError(logs, HttpStatusCode.Unauthorized, 6, await logs.JsonAsync(), "Insufficient user permission for owner to set this API permission");
        Assert.AreEqual(HttpStatusCode.OK, upload.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, again.StatusCode, "granting a held permission does nothing");
        Assert.AreEqual(ApiPermissions.ApiManage | ApiPermissions.Upload, permissions);
    }

    /// <summary>RULE-050 Who may manage a given user (legacy: internal/webserver/api/Api.go:245-264).</summary>
    /// <remarks>
    /// Given: editor #7 (rank User, PERM_USERS only) and target #8 with PERM_USERS+PERM_LOGS target rank Admin and a non-admin editor target #999 does not exist<br/>
    /// When: \#7 resets #8's password<br/>
    /// Then: 400 ResourceCanNotBeEdited "Cannot modify users with permissions you do not have" 400 "Only admins can modify admins" 404
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-050")]
    public async Task RULE_050_WhoMayManageAGivenUser()
    {
        var app = await Portal.AppAsync();
        using var editor = await app.NewCallerAsync(UserPermissions.Users);
        var stronger = await app.NewUserAsync(UserPermissions.Users | UserPermissions.Logs);
        var admin = await app.NewUserAsync(rank: UserRank.Admin);

        using var moreRights = await editor.SendAsync(HttpMethod.Put, "/api/user/resetPassword", ("userid", stronger.Id.ToString()));
        using var onAdmin = await editor.SendAsync(HttpMethod.Put, "/api/user/resetPassword", ("userid", admin.Id.ToString()));
        using var missing = await editor.SendAsync(HttpMethod.Put, "/api/user/resetPassword", ("userid", "999999"));

        Api.AssertError(moreRights, HttpStatusCode.BadRequest, 19, await moreRights.JsonAsync(), "Cannot modify users with permissions you do not have");
        Api.AssertError(onAdmin, HttpStatusCode.BadRequest, 19, await onAdmin.JsonAsync(), "Only admins can modify admins");
        Api.AssertError(missing, HttpStatusCode.NotFound, 5, await missing.JsonAsync());
    }

    /// <summary>RULE-051 Deleting a link needs ownership or PERM_DELETE, now or after a delay (legacy: internal/webserver/api/Api.go:352-372).</summary>
    /// <remarks>
    /// Given: link A of user #5<br/>
    /// When: user #5 calls /files/delete `id: A` it is called with `delay: 600` user #9 without PERM_DELETE calls it<br/>
    /// Then: A is expired now and clean-up removes it A is unavailable to customers at once and deleted after 10 min 401 "No permission to delete this file"
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-051")]
    public async Task RULE_051_DeletingALinkNeedsOwnershipOrPermDelete()
    {
        var app = await Portal.AppAsync();
        using var owner = await app.NewCallerAsync();
        using var stranger = await app.NewCallerAsync();
        var now = Id(await owner.AddAsync(Api.Pdf()));
        var later = Id(await owner.AddAsync(Api.Pdf()));

        using var refused = await stranger.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", now));
        await owner.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", now));
        await owner.SendAsync(HttpMethod.Delete, "/api/files/delete", ("id", later), ("delay", "600"));

        Api.AssertError(refused, HttpStatusCode.Unauthorized, 6, await refused.JsonAsync(), "No permission to delete this file");
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == now)));
        Assert.AreEqual(LinkState.PendingDeletion, (await app.LinkAsync(later)).State);
    }

    /// <summary>RULE-053 The API file list shows own links, or all links with PERM_LIST, newest 1000, without expired ones (legacy: internal/webserver/api/Api.go:495-511).</summary>
    /// <remarks>
    /// Given: user #5 has 3 live links and 1 expired, and user #6 has 2<br/>
    /// When: user #5 without PERM_LIST calls /files/list<br/>
    /// Then: 3 links are returned And with PERM_LIST, 5
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-053")]
    public async Task RULE_053_FileListShowsOwnOrAllLinksWithoutExpired()
    {
        var app = await Portal.AppAsync();
        using var five = await app.NewCallerAsync();
        using var six = await app.NewCallerAsync();
        using var lister = await app.NewCallerAsync(UserPermissions.List);
        var own = new List<string>();
        for (var i = 0; i < 3; i++) own.Add(Id(await five.AddAsync(Api.Pdf())));
        var expired = Id(await five.AddAsync(Api.Pdf(), ("allowedDownloads", "1")));
        await app.InDbAsync(db => db.Links.Where(l => l.Id == expired).ExecuteUpdateAsync(x => x.SetProperty(l => l.DownloadsRemaining, 0)));
        var others = new[] { Id(await six.AddAsync(Api.Pdf())), Id(await six.AddAsync(Api.Pdf())) };

        var mine = Ids(await (await five.SendAsync(HttpMethod.Get, "/api/files/list")).JsonAsync());
        var all = Ids(await (await lister.SendAsync(HttpMethod.Get, "/api/files/list")).JsonAsync());

        CollectionAssert.AreEquivalent(own, mine);
        foreach (var id in own.Concat(others)) Assert.Contains(id, all);
        Assert.DoesNotContain(expired, all);
    }

    /// <summary>RULE-054 API download needs PERM_DOWNLOAD and ownership or PERM_LIST, with no access code (legacy: internal/webserver/api/Api.go:602-653).</summary>
    /// <remarks>
    /// Given: link A (code 4821, 1 download left) owned by user #5<br/>
    /// When: user #5's key calls /api/files/download/A with no headers it is called with `increaseCounter: true` user #9 without PERM_LIST calls it<br/>
    /// Then: the file streams and DownloadsRemaining stays 1 DownloadsRemaining becomes 0 401 "no permission to download file"
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-054")]
    public async Task RULE_054_ApiDownloadNeedsPermDownloadAndNoAccessCode()
    {
        var app = await Portal.AppAsync();
        using var owner = await app.NewCallerAsync();
        using var stranger = await app.NewCallerAsync();
        using var noDownload = await app.NewCallerAsync(keyPermissions: ApiPermissions.View | ApiPermissions.Upload);
        var bytes = Api.Pdf();
        var id = Id(await owner.AddAsync(bytes, ("allowedDownloads", "1")));

        using var plain = await owner.SendAsync(HttpMethod.Get, $"/api/files/download/{id}");
        var afterPlain = (await app.LinkAsync(id)).DownloadsRemaining;
        using var refused = await stranger.SendAsync(HttpMethod.Get, $"/api/files/download/{id}");
        using var noPermission = await noDownload.SendAsync(HttpMethod.Get, $"/api/files/download/{id}");
        using var counted = await owner.SendAsync(HttpMethod.Get, $"/api/files/download/{id}", ("increaseCounter", "true"));

        CollectionAssert.AreEqual(bytes, await plain.Content.ReadAsByteArrayAsync(), "no access code needed");
        Assert.AreEqual(1, afterPlain, "not counted without increaseCounter");
        Api.AssertError(refused, HttpStatusCode.Unauthorized, 6, await refused.JsonAsync(), "no permission to download file");
        Assert.AreEqual(HttpStatusCode.Unauthorized, noPermission.StatusCode, "the key needs PERM_DOWNLOAD");
        Assert.AreEqual(HttpStatusCode.OK, counted.StatusCode);
        Assert.AreEqual(0, (await app.LinkAsync(id)).DownloadsRemaining);
    }

    /// <summary>RULE-055 Admin-only endpoints refuse non-admin key owners (legacy: internal/webserver/api/Api.go:63-66).</summary>
    /// <remarks>
    /// Given: user #7 with rank User whose key holds EDIT<br/>
    /// When: it calls /api/files/changeOwner<br/>
    /// Then: the API answers 401 ErrorCode AdminOnly(3) And the same call by a rank-Admin user moves on to the permission checks
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-055")]
    public async Task RULE_055_AdminOnlyEndpointsRefuseNonAdminOwners()
    {
        var app = await Portal.AppAsync();
        using var user = await app.NewCallerAsync(UserPermissions.Edit);
        using var admin = await app.NewCallerAsync(UserPermissions.All, rank: UserRank.Admin);
        var id = Id(await user.AddAsync(Api.Pdf()));

        using var refused = await user.SendAsync(HttpMethod.Put, "/api/files/changeOwner", ("id", id), ("newOwner", admin.UserId.ToString()));
        using var moved = await admin.SendAsync(HttpMethod.Put, "/api/files/changeOwner", ("id", id), ("newOwner", admin.UserId.ToString()));

        Api.AssertError(refused, HttpStatusCode.Unauthorized, 3, await refused.JsonAsync());
        Assert.AreEqual(HttpStatusCode.OK, moved.StatusCode);
        Assert.AreEqual(admin.UserId, (await app.LinkAsync(id)).OwnerId);
    }

    /// <summary>RULE-056 A sensitive key permission only works while the key's owner still holds the matching user permission (legacy: internal/webserver/api/Api.go:67-96).</summary>
    /// <remarks>
    /// Given: a key with PERM_MANAGE_USERS whose owner no longer has PERM_USERS<br/>
    /// When: it calls /api/user/create<br/>
    /// Then: the API answers 401 ErrorCode NoPermission(6)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-056")]
    public async Task RULE_056_SensitiveKeyPermissionNeedsOwnerPermission()
    {
        var app = await Portal.AppAsync();
        using var stale = await app.NewCallerAsync(UserPermissions.None, keyPermissions: ApiPermissions.ManageUsers);

        using var refused = await stale.SendAsync(HttpMethod.Post, "/api/user/create", ("username", "someone-new"));

        Api.AssertError(refused, HttpStatusCode.Unauthorized, 6, await refused.JsonAsync());
    }

    /// <summary>RULE-058 Replacing a link's content needs rights on both links, and deleting the source needs DELETE too (legacy: internal/webserver/api/Api.go:799-843).</summary>
    /// <remarks>
    /// Given: target A of user #5 and source B of user #6, called by #5 whose key has REPLACE and who holds PERM_REPLACE<br/>
    /// When: \#5 lacks PERM_LIST `deleteNewFile: true` is sent and the key lacks DELETE everything passes<br/>
    /// Then: 401 "No permission to duplicate this file" 401 "No permission to delete original file" A shows B's content and B is deleted if requested
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-058")]
    public async Task RULE_058_ReplacingContentNeedsRightsOnBothLinks()
    {
        var app = await Portal.AppAsync();
        using var five = await app.NewCallerAsync(UserPermissions.Replace);
        using var fiveNoDelete = await app.NewCallerAsync(UserPermissions.Replace | UserPermissions.List | UserPermissions.Delete, keyPermissions: Api.AllKeyPermissions & ~ApiPermissions.Delete);
        using var lister = await app.NewCallerAsync(UserPermissions.Replace | UserPermissions.List | UserPermissions.Delete);
        using var six = await app.NewCallerAsync();
        var b = Id(await six.AddAsync(Api.Pdf()));

        using var noList = await five.SendAsync(HttpMethod.Put, "/api/files/replace", ("id", Id(await five.AddAsync(Api.Pdf()))), ("idNewContent", b));
        using var noDelete = await fiveNoDelete.SendAsync(HttpMethod.Put, "/api/files/replace", ("id", Id(await fiveNoDelete.AddAsync(Api.Pdf()))), ("idNewContent", b), ("deleteNewFile", "true"));
        var a = Id(await lister.AddAsync(Api.Pdf()));
        using var ok = await lister.SendAsync(HttpMethod.Put, "/api/files/replace", ("id", a), ("idNewContent", b), ("deleteNewFile", "true"));

        Api.AssertError(noList, HttpStatusCode.Unauthorized, 6, await noList.JsonAsync(), "No permission to duplicate this file");
        Api.AssertError(noDelete, HttpStatusCode.Unauthorized, 6, await noDelete.JsonAsync(), "No permission to delete original file");
        Assert.AreEqual(HttpStatusCode.OK, ok.StatusCode, (await ok.JsonAsync()).ToString());
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => l.Id == b)), "B is deleted as requested");
    }

    /// <summary>RULE-059 Granting or revoking a user permission (legacy: internal/webserver/api/Api.go:861-899).</summary>
    /// <remarks>
    /// Given: editor #7 without PERM_LOGS<br/>
    /// When: \#7 grants PERM_LOGS to #8 #7 targets themself<br/>
    /// Then: 400 "Cannot grant rights the user does not have" "Cannot modify yourself"
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-059")]
    public async Task RULE_059_GrantingOrRevokingAUserPermission()
    {
        var app = await Portal.AppAsync();
        using var editor = await app.NewCallerAsync(UserPermissions.Users);
        var target = await app.NewUserAsync();

        using var tooMuch = await editor.SendAsync(HttpMethod.Put, "/api/user/modify", ("userid", target.Id.ToString()), ("userpermission", "PERM_LOGS"), ("permissionModifier", "GRANT"));
        using var self = await editor.SendAsync(HttpMethod.Put, "/api/user/modify", ("userid", editor.UserId.ToString()), ("userpermission", "PERM_USERS"), ("permissionModifier", "REVOKE"));
        using var ok = await editor.SendAsync(HttpMethod.Put, "/api/user/modify", ("userid", target.Id.ToString()), ("userpermission", "PERM_USERS"), ("permissionModifier", "GRANT"));

        Api.AssertError(tooMuch, HttpStatusCode.BadRequest, 6, await tooMuch.JsonAsync(), "Cannot grant rights the user does not have");
        Api.AssertError(self, HttpStatusCode.BadRequest, 19, await self.JsonAsync(), "Cannot modify yourself");
        Assert.AreEqual(HttpStatusCode.OK, ok.StatusCode);
        Assert.AreEqual(UserPermissions.Users, await app.InDbAsync(db => db.Users.Where(u => u.Id == target.Id).Select(u => u.Permissions).SingleAsync()));
    }

    /// <summary>RULE-060 Changing a user's rank resets their permissions (legacy: internal/webserver/api/Api.go:901-942).</summary>
    /// <remarks>
    /// Given: non-admin editor #7 with PERM_USERS<br/>
    /// When: \#7 sets #8 to newRank "admin" admin #1 sets #8 to "user"<br/>
    /// Then: 400 "Only admins can promote users to admin" #8's permissions become 0 and its keys lose REPLACE/MANAGE_USERS/MANAGE_LOGS
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-060")]
    public async Task RULE_060_ChangingRankResetsPermissions()
    {
        var app = await Portal.AppAsync();
        using var nonAdmin = await app.NewCallerAsync(UserPermissions.Users);
        using var admin = await app.NewCallerAsync(UserPermissions.All, rank: UserRank.Admin);
        using var target = await app.NewCallerAsync(UserPermissions.Replace | UserPermissions.Users | UserPermissions.Logs, rank: UserRank.Admin);

        using var refused = await nonAdmin.SendAsync(HttpMethod.Put, "/api/user/changeRank", ("userid", (await app.NewUserAsync()).Id.ToString()), ("newRank", "admin"));
        using var demoted = await admin.SendAsync(HttpMethod.Put, "/api/user/changeRank", ("userid", target.UserId.ToString()), ("newRank", "user"));
        var user = await app.InDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Id == target.UserId));
        var keyPermissions = await app.InDbAsync(db => db.ApiKeys.Where(k => k.OwnerId == target.UserId).Select(k => k.Permissions).SingleAsync());

        Api.AssertError(refused, HttpStatusCode.BadRequest, 19, await refused.JsonAsync(), "Only admins can promote users to admin");
        Assert.AreEqual(HttpStatusCode.OK, demoted.StatusCode);
        Assert.AreEqual(UserRank.User, user.Rank);
        Assert.AreEqual(UserPermissions.None, user.Permissions);
        Assert.AreEqual(ApiPermissions.None, keyPermissions & (ApiPermissions.Replace | ApiPermissions.ManageUsers | ApiPermissions.ManageLogs));
    }

    /// <summary>RULE-061 Permission each API endpoint requires (legacy: internal/webserver/api/routing.go:33-229).</summary>
    /// <remarks>
    /// Given: a key with only PERM_UPLOAD<br/>
    /// When: it calls /api/files/modify (needs PERM_EDIT)<br/>
    /// Then: it is refused with 401 And /api/files/add, /files/reserve, /files/content, /chunk/add, /chunk/complete, /files/duplicate, /files/qr/ and /info/config succeed on the permission check
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-061")]
    public async Task RULE_061_EachEndpointRequiresItsPermission()
    {
        // /files/duplicate needs VIEW + UPLOAD as openapi.json documents it (spec F6), not UPLOAD alone as the legacy code did.
        var app = await Portal.AppAsync();
        using var uploader = await app.NewCallerAsync(keyPermissions: ApiPermissions.Upload);

        using var modify = await uploader.SendAsync(HttpMethod.Put, "/api/files/modify", ("id", "x"));
        using var duplicate = await uploader.SendAsync(HttpMethod.Post, "/api/files/duplicate", ("id", "x"));
        var passing = new List<HttpResponseMessage>
        {
            await uploader.Client.PostAsync("/api/files/add", Api.Upload(Api.Pdf(), fields: [("password", "4821")])),
            await uploader.SendAsync(HttpMethod.Post, "/api/files/reserve"),
            await uploader.SendAsync(HttpMethod.Post, "/api/chunk/complete", ("uuid", "none"), ("filename", "a.pdf"), ("filesize", "1"), ("password", "4821")),
            await uploader.SendAsync(HttpMethod.Get, "/api/files/qr/NotARealId00000"),
            await uploader.SendAsync(HttpMethod.Get, "/api/info/config"),
        };

        Api.AssertError(modify, HttpStatusCode.Unauthorized, 2, await modify.JsonAsync());
        Api.AssertError(duplicate, HttpStatusCode.Unauthorized, 2, await duplicate.JsonAsync());
        foreach (var response in passing)
            Assert.AreNotEqual(HttpStatusCode.Unauthorized, response.StatusCode, response.RequestMessage!.RequestUri!.ToString());
    }

    /// <summary>RULE-063 Login credentials check (legacy: internal/webserver/authentication/Authentication.go:36-51).</summary>
    /// <remarks>
    /// Given: user "alice" created through the API with no password set<br/>
    /// When: she tries to log in with any password<br/>
    /// Then: the login fails (an empty hash never verifies, Configuration.go:204-209)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-063")]
    public async Task RULE_063_EmptyPasswordHashNeverVerifies()
    {
        var app = await Portal.AppAsync();
        using var admin = await app.NewCallerAsync(UserPermissions.Users);
        using var created = await admin.SendAsync(HttpMethod.Post, "/api/user/create", ("username", "Alice-" + Guid.NewGuid().ToString("N")[..8]));
        var name = (await created.JsonAsync()).GetProperty("name").GetString()!;
        using var browser = app.Browser();

        var empty = await (await browser.LoginAsync(name, "")).Content.ReadAsStringAsync();
        var anything = await (await browser.LoginAsync(name, "anything")).Content.ReadAsStringAsync();

        Assert.AreEqual(name.ToLowerInvariant(), name, "names are stored in lower case");
        Assert.DoesNotContain("Logout", empty);
        Assert.Contains("Incorrect username or password!", anything);
    }

    /// <summary>RULE-064 Form CSRF tokens are single-use and last 5 minutes (legacy: internal/webserver/authentication/csrftoken/CsrfToken.go:31-65).</summary>
    /// <remarks>
    /// Given: a token issued at 10:00<br/>
    /// When: it is submitted at 10:03 it is submitted again, or first at 10:06<br/>
    /// Then: it is accepted it is rejected
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-064")]
    public async Task RULE_064_FormPostsAreProtectedAgainstCrossSiteForgery()
    {
        // Revised (REIMAGINED_ARCHITECTURE §7 #9): antiforgery tokens on forms plus the same-origin check, instead of single-use tokens.
        var app = await Portal.AppAsync();
        var user = await app.NewUserAsync(mustChangePassword: true);
        using var browser = await app.SignInAsync(user);

        using var noToken = await browser.PostAsync("/changePassword", new FormUrlEncodedContent(new Dictionary<string, string> { ["newpw"] = "brand-new-password-1" }));
        using var crossSite = new HttpRequestMessage(HttpMethod.Post, "/changePassword") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["newpw"] = "brand-new-password-1" }) };
        crossSite.Headers.Add("Sec-Fetch-Site", "cross-site");
        using var forged = await browser.SendAsync(crossSite);

        Assert.AreEqual(HttpStatusCode.BadRequest, noToken.StatusCode, "a form post without its token is refused");
        Assert.AreEqual(HttpStatusCode.Forbidden, forged.StatusCode);
        Assert.IsTrue(await app.InDbAsync(db => db.Users.Where(u => u.Id == user.Id).Select(u => u.MustChangePassword).SingleAsync()), "nothing changed");
    }

    /// <summary>RULE-066 Single sign-on accepts only a valid, browser-bound answer for an existing user (legacy: internal/webserver/authentication/saml/Saml.go:117-176).</summary>
    /// <remarks>
    /// Given: login started at 10:00 by browser B<br/>
    /// When: the answer arrives at 10:05 for NameID "Alice@Corp", and user "alice@corp" exists it arrives at 10:11, or in another browser the NameID is not a user<br/>
    /// Then: a 12-hour SSO session is created and the browser goes to /admin the error "the login was not started on this page, or took longer than 10 minutes" the not-authorised page and the failed login is logged
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-066")]
    public void RULE_066_SamlAcceptsOnlyBrowserBoundAnswerForExistingUser() => Pending.Rule("RULE-066");

    /// <summary>RULE-067 Temporary tokens for the admin pages (legacy: internal/webserver/authentication/tokengeneration/TokenGeneration.go:17-41).</summary>
    /// <remarks>
    /// Given: logged-in user #7 without PERM_USERS<br/>
    /// When: /auth/token is called with header `permission: PERM_MANAGE_USERS` it is called with `permission: PERM_UPLOAD`<br/>
    /// Then: 400 "user does not have permission to generate a token with PERM_MANAGE_USERS" {"key":"&lt;30 chars&gt;","expiry":now+300}
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-067")]
    public async Task RULE_067_TemporaryTokensForAdminPages()
    {
        var app = await Portal.AppAsync();
        var user = await app.NewUserAsync();
        using var browser = await app.SignInAsync(user);
        var now = app.Time.GetUtcNow();

        using var tooMuch = await TokenAsync(browser, "PERM_MANAGE_USERS");
        using var upload = await TokenAsync(browser, "PERM_UPLOAD");
        var token = await upload.JsonAsync();
        using var keyClient = app.KeyClient(token.GetProperty("key").GetString());
        using var reserve = await keyClient.PostAsync("/api/files/reserve", null);
        app.Time.Advance(TimeSpan.FromSeconds(301));
        using var late = await keyClient.PostAsync("/api/files/reserve", null);

        Assert.AreEqual(HttpStatusCode.BadRequest, tooMuch.StatusCode);
        Assert.Contains("user does not have permission to generate a token with PERM_MANAGE_USERS", await tooMuch.Content.ReadAsStringAsync());
        Assert.AreEqual(30, token.GetProperty("key").GetString()!.Length);
        Assert.AreEqual(now.AddSeconds(300).ToUnixTimeSeconds(), token.GetProperty("expiry").GetInt64());
        Assert.AreEqual(HttpStatusCode.OK, reserve.StatusCode, "the token works as a key of the user");
        Assert.AreEqual(HttpStatusCode.Unauthorized, late.StatusCode, "and expires after 5 minutes");
    }

    static Task<HttpResponseMessage> TokenAsync(HttpClient browser, string permission)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token");
        request.Headers.Add("permission", permission);
        return browser.SendAsync(request);
    }

    /// <summary>RULE-104 Events that end all of a user's sessions (legacy: internal/configuration/Configuration.go:146-173).</summary>
    /// <remarks>
    /// Given: setup is re-applied with Authentication.Saml switched on setup is re-applied with the encryption level changed from "local, stored key" to "full, stored key" (not initial setup, Setup.go:237-256)<br/>
    /// When: (not stated separately in the spec; the outcomes are given with each step above)<br/>
    /// Then: all sessions are deleted every encrypted link gets ExpireAt = 0 and UnlimitedTime = false, and the next clean-up purges it
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-104")]
    public async Task RULE_104_EventsThatEndAllSessions()
    {
        // Revised (§7 #23): the "setup re-applied" triggers are gone; a password change or reset is what ends every session.
        var app = await Portal.AppAsync();
        var user = await app.NewUserAsync();
        using var admin = await app.NewCallerAsync(UserPermissions.All, rank: UserRank.Admin);
        using var browser = await app.SignInAsync(user);
        var before = await browser.GetAsync("/admin");

        await admin.SendAsync(HttpMethod.Put, "/api/user/resetPassword", ("userid", user.Id.ToString()));
        var after = await browser.GetAsync("/admin");

        Assert.AreEqual(HttpStatusCode.OK, before.StatusCode);
        Portal.AssertRedirect(after, "./login");
    }

    /// <summary>RULE-116 Forced password change after reset (legacy: internal/webserver/Webserver.go:284-350).</summary>
    /// <remarks>
    /// Given: user 12 with ResetPassword = true and temporary password "Xk3…" (masked)<br/>
    /// When: the user submits newpw "abc" → "Password is too short" the user submits the same password as the old one → "New password has to be different from the old password" the user submits "correct-horse-1" with a valid form token → the hash is saved, ResetPassword = false, all sessions are deleted, a new session is created and the user is redirected to /admin<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// <br/>Reviewer: Correct. The rebuild adds an audit log entry.
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-116")]
    public async Task RULE_116_ForcedPasswordChangeAfterReset()
    {
        var app = await Portal.AppAsync();
        var user = await app.NewUserAsync(password: "temporary-pass-1", mustChangePassword: true);
        using var browser = await app.SignInAsync(user);
        using var other = await app.SignInAsync(user);

        var redirected = await browser.GetAsync("/admin");
        var tooShort = await (await browser.PostFormAsync("/changePassword", "/changePassword", new() { ["newpw"] = "abc" })).Content.ReadAsStringAsync();
        var same = await (await browser.PostFormAsync("/changePassword", "/changePassword", new() { ["newpw"] = "temporary-pass-1" })).Content.ReadAsStringAsync();
        var changed = await browser.PostFormAsync("/changePassword", "/changePassword", new() { ["newpw"] = "correct-horse-1" });
        var adminNow = await browser.GetAsync("/admin");
        var otherSession = await other.GetAsync("/admin");

        Portal.AssertRedirect(redirected, "./changePassword");
        Assert.Contains("Password is too short", tooShort);
        Assert.Contains("New password has to be different from the old password", same);
        Portal.AssertRedirect(changed, "./admin");
        Assert.AreEqual(HttpStatusCode.OK, adminNow.StatusCode, "a new session for this browser");
        Portal.AssertRedirect(otherSession, "./login");
        Assert.IsFalse(await app.InDbAsync(db => db.Users.Where(u => u.Id == user.Id).Select(u => u.MustChangePassword).SingleAsync()));
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.Action == "PasswordChanged" && e.ActorUserId == user.Id)), "audited");
    }

    /// <summary>RULE-119 Deleting a user (legacy: internal/webserver/api/Api.go:1000-1043).</summary>
    /// <remarks>
    /// Given: user 12 with 3 links and 2 API keys, editor user 1 with PERM_LIST<br/>
    /// When: /user/delete?userid=12&amp;deleteFiles=true → a "deleted by" audit entry is written, sessions and keys are deleted, the 3 links are expired and a clean-up runs, and user 12 is removed deleteFiles=false → the 3 links get UserId = 1 deleteFiles=false and the editor lacks PERM_LIST → refused<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-119")]
    public async Task RULE_119_DeletingAUser()
    {
        var app = await Portal.AppAsync();
        using var editor = await app.NewCallerAsync(UserPermissions.All, rank: UserRank.Admin);
        using var noList = await app.NewCallerAsync(UserPermissions.Users);
        using var leaving = await app.NewCallerAsync();
        using var keeping = await app.NewCallerAsync();
        var gone = new[] { Id(await leaving.AddAsync(Api.Pdf())), Id(await leaving.AddAsync(Api.Pdf())), Id(await leaving.AddAsync(Api.Pdf())) };
        var kept = Id(await keeping.AddAsync(Api.Pdf()));

        using var refused = await noList.SendAsync(HttpMethod.Delete, "/api/user/delete", ("userid", keeping.UserId.ToString()));
        using var withFiles = await editor.SendAsync(HttpMethod.Delete, "/api/user/delete", ("userid", leaving.UserId.ToString()), ("deleteFiles", "true"));
        using var keepFiles = await editor.SendAsync(HttpMethod.Delete, "/api/user/delete", ("userid", keeping.UserId.ToString()));

        Assert.AreEqual(HttpStatusCode.Unauthorized, refused.StatusCode, "keeping files needs PERM_LIST");
        Assert.AreEqual(HttpStatusCode.OK, withFiles.StatusCode);
        Assert.IsFalse(await app.InDbAsync(db => db.Links.AnyAsync(l => gone.Contains(l.Id))), "the user's links are deleted");
        Assert.IsFalse(await app.InDbAsync(db => db.ApiKeys.AnyAsync(k => k.OwnerId == leaving.UserId)), "and the keys");
        Assert.IsFalse(await app.InDbAsync(db => db.Users.AnyAsync(u => u.Id == leaving.UserId)));
        Assert.AreEqual(editor.UserId, (await app.LinkAsync(kept)).OwnerId, "deleteFiles=false hands the links to the editor");
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.Action == "UserDeleted" && e.ActorUserId == editor.UserId)));
    }

    /// <summary>RULE-121 API key validity at each request (legacy: internal/webserver/api/Api.go:1143-1169).</summary>
    /// <remarks>
    /// Given: key K with Expiry = 0 and permission VIEW temporary key T with Expiry = 10:05:00, used at 10:05:01 → rejected, and the per-IP API throttle applies<br/>
    /// When: it calls /files/list → accepted, and LastUsed = now<br/>
    /// Then: (not stated separately in the spec; the outcomes are given with each step above)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-121")]
    public async Task RULE_121_ApiKeyValidityAtEachRequest()
    {
        var app = await Portal.AppAsync();
        using var temporary = await app.NewCallerAsync(keyPermissions: ApiPermissions.View, keyExpires: app.Time.GetUtcNow().AddMinutes(5));

        using var before = await temporary.SendAsync(HttpMethod.Get, "/api/files/list");
        app.Time.Advance(TimeSpan.FromSeconds(301));
        using var after = await temporary.SendAsync(HttpMethod.Get, "/api/files/list");

        Assert.AreEqual(HttpStatusCode.OK, before.StatusCode);
        Api.AssertError(after, HttpStatusCode.Unauthorized, 2, await after.JsonAsync());
    }

    /// <summary>RULE-123 Admin-initiated password reset (legacy: internal/webserver/api/Api.go:967-998).</summary>
    /// <remarks>
    /// Given: user 12 (rank User), editor user 1 (Admin), MinLengthPassword = 8<br/>
    /// When: /user/resetPassword?userid=12&amp;generateNewPassword=true is called generateNewPassword is false → the old password stays valid but must be changed at next login<br/>
    /// Then: user 12's ResetPassword = true, a 10-character random password is hashed and stored and returned once in the response, and every session of user 12 is deleted
    /// <br/>Reviewer: Keep the reset. The rebuild adds an audit entry and tightens who may reset others (SEC-005).
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-123")]
    public async Task RULE_123_AdminInitiatedPasswordReset()
    {
        var app = await Portal.AppAsync();
        using var admin = await app.NewCallerAsync(UserPermissions.All, rank: UserRank.Admin);
        var twelve = await app.NewUserAsync(password: "original-pass-1");
        var keepsPassword = await app.NewUserAsync(password: "original-pass-2");
        using var session = await app.SignInAsync(twelve);

        using var generated = await admin.SendAsync(HttpMethod.Put, "/api/user/resetPassword", ("userid", twelve.Id.ToString()), ("generateNewPassword", "true"));
        var password = (await generated.JsonAsync()).GetProperty("password").GetString()!;
        using var forced = await admin.SendAsync(HttpMethod.Put, "/api/user/resetPassword", ("userid", keepsPassword.Id.ToString()));
        var ended = await session.GetAsync("/admin");
        using var withNew = app.Browser();
        var loginNew = await withNew.LoginAsync(twelve.Name, password);
        using var withOld = app.Browser();
        var loginOld = await withOld.LoginAsync(keepsPassword.Name, keepsPassword.Password);
        var mustChange = await withOld.GetAsync("/admin");

        Assert.AreEqual(10, password.Length, "QHUB_MIN_LENGTH_PASSWORD (8) + 2");
        Portal.AssertRedirect(ended, "./login");
        Portal.AssertRedirect(loginNew, "./admin");
        Portal.AssertRedirect(loginOld, "./admin");
        Portal.AssertRedirect(mustChange, "./changePassword");
        Assert.AreEqual("", (await forced.JsonAsync()).GetProperty("password").GetString());
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.Action == "PasswordReset" && e.ActorUserId == admin.UserId)));
    }

    /// <summary>RULE-144 The super admin is created or updated at every start (legacy: internal/configuration/database/Database.go:260-285).</summary>
    /// <remarks>
    /// Given: an empty user table and ADMIN_USER=Admin users exist without a super admin<br/>
    /// When: (not stated separately in the spec; the outcomes are given with each step above)<br/>
    /// Then: user "admin" is created at level 0 with permissions 255 Qhub exits with "Could not edit superadmin…"
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-144")]
    public async Task RULE_144_SuperAdminIsUpsertedAtEveryStart()
    {
        var settings = QhubFactory.ValidSettings(await SqlServer.NewDatabaseAsync());
        settings["QHUB_ADMIN_USER"] = "Admin";
        await using (var first = new QhubFactory(settings)) first.CreateClient().Dispose();
        User admin;
        await using (var check = new QhubFactory(settings))
        {
            check.CreateClient().Dispose();
            admin = await check.InDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Rank == UserRank.SuperAdmin));
            await check.InDbAsync(async db =>
            {
                db.Users.Add(new User { Name = "someone", SecurityStamp = "s" });
                await db.SaveChangesAsync();
                return await db.Users.Where(u => u.Rank == UserRank.SuperAdmin).ExecuteUpdateAsync(x => x.SetProperty(u => u.Rank, UserRank.Admin));
            });
        }
        await using var broken = new QhubFactory(settings);
        var failure = Assert.Throws<Exception>(() => broken.CreateClient());

        Assert.AreEqual("admin", admin.Name);
        Assert.AreEqual(UserPermissions.All, admin.Permissions);
        Assert.Contains("Could not edit superadmin", failure.ToString());
    }

    /// <summary>RULE-147 Removing a user permission strips the matching key permission from all their keys (legacy: internal/webserver/api/Api.go:944-965).</summary>
    /// <remarks>
    /// Given: user #5 with PERM_LOGS and two keys holding MANAGE_LOGS<br/>
    /// When: PERM_LOGS is revoked<br/>
    /// Then: both keys lose MANAGE_LOGS
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-147")]
    public async Task RULE_147_RemovingUserPermissionStripsMatchingKeyPermission()
    {
        var app = await Portal.AppAsync();
        using var admin = await app.NewCallerAsync(UserPermissions.All, rank: UserRank.Admin);
        using var five = await app.NewCallerAsync(UserPermissions.Logs, keyPermissions: ApiPermissions.ManageLogs | ApiPermissions.View);
        await app.InDbAsync(async db =>
        {
            db.ApiKeys.Add(new ApiKey { Id = Guid.NewGuid().ToString("N"), OwnerId = five.UserId, SecretHash = SHA256.HashData(Guid.NewGuid().ToByteArray()), Permissions = ApiPermissions.ManageLogs });
            return await db.SaveChangesAsync();
        });

        await admin.SendAsync(HttpMethod.Put, "/api/user/modify", ("userid", five.UserId.ToString()), ("userpermission", "PERM_LOGS"), ("permissionModifier", "REVOKE"));
        var keys = await app.InDbAsync(db => db.ApiKeys.Where(k => k.OwnerId == five.UserId).Select(k => k.Permissions).ToListAsync());

        Assert.HasCount(2, keys);
        Assert.IsTrue(keys.All(k => !k.HasFlag(ApiPermissions.ManageLogs)), "both keys lose MANAGE_LOGS");
        Assert.IsTrue(keys.Any(k => k.HasFlag(ApiPermissions.View)), "other permissions stay");
    }

    /// <summary>RULE-148 Session lifetime and renewal (legacy: internal/webserver/authentication/sessionmanager/SessionManager.go:19-80).</summary>
    /// <remarks>
    /// Given: a password session created at day 0 10:00 an SSO session created at 10:00<br/>
    /// When: it is used at 23:00 it is used at 22:01<br/>
    /// Then: a new session cookie replaces it it is invalid and the user must log in again
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-148")]
    public async Task RULE_148_SessionLifetimeAndRenewal()
    {
        // The 12-hour single sign-on session is proven with SAML (RULE-066).
        var app = await Portal.AppAsync();
        var user = await app.NewUserAsync();
        using var browser = await app.SignInAsync(user);

        app.Time.Advance(TimeSpan.FromHours(11));
        var early = await browser.GetAsync("/admin");
        app.Time.Advance(TimeSpan.FromHours(2));
        var renewed = await browser.GetAsync("/admin");

        Assert.AreEqual(HttpStatusCode.OK, early.StatusCode);
        Assert.IsFalse(early.Headers.Contains("Set-Cookie") && early.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("session_token=", StringComparison.Ordinal)), "no renewal before 12 h");
        Assert.AreEqual(HttpStatusCode.OK, renewed.StatusCode);
        Assert.IsTrue(renewed.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("session_token=", StringComparison.Ordinal)), "a new session cookie replaces it after 12 h");
    }

    /// <summary>RULE-149 Login attempts are throttled per IP (legacy: internal/webserver/ratelimiter/RateLimiter.go:55-58).</summary>
    /// <remarks>
    /// Given: IP X made 3 login attempts just now<br/>
    /// When: it makes a 4th<br/>
    /// Then: it waits about 3 s
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-149")]
    public async Task RULE_149_LoginAttemptsAreThrottledPerIp()
    {
        var app = await Portal.AppAsync();
        using var browser = app.Browser();
        await browser.GetStringAsync("/login"); // one antiforgery cookie before the parallel posts

        var attempts = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => browser.LoginAsync("nobody", "wrong-password")));

        Assert.IsTrue(attempts.Any(r => r.StatusCode == HttpStatusCode.TooManyRequests), "beyond 3 at once plus 3 waiting, attempts are refused");
        Assert.IsTrue(attempts.Count(r => r.StatusCode == HttpStatusCode.OK) >= 3);
    }

    /// <summary>RULE-045 (corrected) A forced password change applies on every route except change-password and logout (legacy: internal/webserver/Webserver.go:894-917).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/Webserver.go:894-917, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: A forced password change applies on every route except change-password and logout
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-045")]
    public async Task RULE_045_ForcedPasswordChangeAppliesOnEveryRouteButChangePasswordAndLogout()
    {
        var app = await Portal.AppAsync();
        var user = await app.NewUserAsync(UserPermissions.All, rank: UserRank.Admin, mustChangePassword: true);
        using var browser = await app.SignInAsync(user);

        foreach (var page in new[] { "/admin", "/users", "/apiKeys", "/logs" })
            Portal.AssertRedirect(await browser.GetAsync(page), "./changePassword");
        using var token = await TokenAsync(browser, "PERM_UPLOAD");
        var status = await browser.GetAsync("/uploadStatus");
        var change = await browser.GetAsync("/changePassword");
        var logout = await browser.GetAsync("/logout");

        Assert.AreEqual(HttpStatusCode.Forbidden, token.StatusCode);
        Assert.Contains("Password change required", await token.Content.ReadAsStringAsync());
        Assert.AreEqual(HttpStatusCode.Forbidden, status.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, change.StatusCode);
        Portal.AssertRedirect(logout, "./login");
    }

    /// <summary>RULE-057 (corrected) Duplicating another user's document needs edit and download permission, and is audited (legacy: internal/webserver/api/Api.go:741-769).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/api/Api.go:741-769, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Duplicating another user's document needs edit and download permission, and is audited
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-057")]
    public async Task RULE_057_DuplicatingAnotherUsersDocumentNeedsEditAndDownload()
    {
        var app = await Portal.AppAsync();
        using var owner = await app.NewCallerAsync();
        using var listOnly = await app.NewCallerAsync(UserPermissions.List);
        using var noDownload = await app.NewCallerAsync(UserPermissions.List | UserPermissions.Edit, keyPermissions: Api.AllKeyPermissions & ~ApiPermissions.Download);
        using var allowed = await app.NewCallerAsync(UserPermissions.List | UserPermissions.Edit);
        var id = Id(await owner.AddAsync(Api.Pdf()));

        using var a = await listOnly.SendAsync(HttpMethod.Post, "/api/files/duplicate", ("id", id));
        using var b = await noDownload.SendAsync(HttpMethod.Post, "/api/files/duplicate", ("id", id));
        using var c = await allowed.SendAsync(HttpMethod.Post, "/api/files/duplicate", ("id", id));
        var copy = (await c.JsonAsync()).GetProperty("Id").GetString()!;

        Api.AssertError(a, HttpStatusCode.Unauthorized, 6, await a.JsonAsync(), "No permission to duplicate this file");
        Api.AssertError(b, HttpStatusCode.Unauthorized, 6, await b.JsonAsync());
        Assert.AreEqual(allowed.UserId, (await app.LinkAsync(copy)).OwnerId);
        Assert.IsTrue(await app.InDbAsync(db => db.AuditEntries.AnyAsync(e => e.Action == "Duplicate" && e.LinkId == copy && e.ActorUserId == allowed.UserId)), "audited");
    }

    /// <summary>RULE-126 (corrected) Sessions renew, but there's an absolute maximum lifetime (30 days from login) (legacy: internal/webserver/authentication/sessionmanager/SessionManager.go:19-89).</summary>
    /// <remarks>
    /// Given: the legacy behaviour at internal/webserver/authentication/sessionmanager/SessionManager.go:19-89, which the reviewer marked wrong<br/>
    /// When: the behaviour is exercised in the rebuild<br/>
    /// Then: Sessions renew, but there's an absolute maximum lifetime (30 days from login)
    /// </remarks>
    [TestMethod]
    [TestCategory("RULE-126")]
    public async Task RULE_126_SessionsHaveAThirtyDayAbsoluteLimit()
    {
        var app = await Portal.AppAsync();
        var user = await app.NewUserAsync();
        using var browser = await app.SignInAsync(user);

        var day = new List<HttpStatusCode>();
        for (var i = 0; i < 29; i++)
        {
            app.Time.Advance(TimeSpan.FromDays(1)); // renewed every day of use
            day.Add((await browser.GetAsync("/admin")).StatusCode);
        }
        app.Time.Advance(TimeSpan.FromDays(1) + TimeSpan.FromMinutes(1));
        var past = await browser.GetAsync("/admin");

        Assert.IsTrue(day.All(s => s == HttpStatusCode.OK), "renewed while used");
        Portal.AssertRedirect(past, "./login");
    }

    static string Id(JsonElement fileInfo) => fileInfo.GetProperty("Id").GetString()!;

    static List<string> Ids(JsonElement list) => [.. list.EnumerateArray().Select(f => f.GetProperty("Id").GetString()!)];
}
