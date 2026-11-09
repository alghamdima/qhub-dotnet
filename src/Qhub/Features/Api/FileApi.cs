using System.IO.Compression;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using QRCoder;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Documents;
using Qhub.Features.Storage;
using Qhub.Features.Uploads;
using Qhub.Security;

namespace Qhub.Features.Api;

/// <summary>The <c>/api/files/*</c>, <c>/api/info/*</c> and <c>/api/chunk/*</c> operations of <c>openapi.json</c>.</summary>
public static class FileApi
{
    public static void MapFileApi(this RouteGroupBuilder api)
    {
        api.MapGet("/info/version", () => ApiError.Json(new { Version = "2.1.1", VersionInt = 20101, EndToEndEncryptionEnabled = false }));
        api.MapGet("/info/config", (IOptions<QhubOptions> o) => ApiError.Json(new { MaxFilesize = o.Value.MaxFileSizeMb, MaxChunksize = o.Value.ChunkSizeMb }))
            .Requires(ApiPermissions.Upload);

        api.MapGet("/files/list", ListAsync).Requires(ApiPermissions.View);
        api.MapGet("/files/list/{id}", ListOneAsync).Requires(ApiPermissions.View);
        api.MapGet("/files/qr/{id}", QrAsync).Requires(ApiPermissions.Upload);
        api.MapPost("/files/add", AddAsync).Requires(ApiPermissions.Upload);
        api.MapPost("/files/reserve", ReserveAsync).Requires(ApiPermissions.Upload);
        api.MapPost("/files/content", ContentAsync).Requires(ApiPermissions.Upload);
        api.MapPost("/files/duplicate", DuplicateAsync).Requires(ApiPermissions.View | ApiPermissions.Upload);
        api.MapPut("/files/changeOwner", ChangeOwnerAsync).Requires(ApiPermissions.Edit, adminOnly: true);
        api.MapPut("/files/modify", ModifyAsync).Requires(ApiPermissions.Edit);
        api.MapPut("/files/replace", ReplaceAsync).Requires(ApiPermissions.Replace);
        api.MapDelete("/files/delete", DeleteAsync).Requires(ApiPermissions.Delete);
        api.MapPost("/files/restore", RestoreAsync).Requires(ApiPermissions.Delete);
        api.MapGet("/files/download/{id}", DownloadAsync).Requires(ApiPermissions.Download);
        api.MapGet("/files/downloadzip", DownloadZipAsync).Requires(ApiPermissions.Download);
        api.MapPost("/chunk/add", ChunkAddAsync).Requires(ApiPermissions.Upload);
        api.MapPost("/chunk/complete", ChunkCompleteAsync).Requires(ApiPermissions.Upload);
    }

    /// <summary>Own links, or every link with PERM_LIST; newest 1000; expired ones left out (RULE-053).</summary>
    static async Task<IResult> ListAsync(HttpContext http, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct) =>
        ApiError.Json(await ListForAsync(db, http.Caller().User, time.GetUtcNow(), o.Value.PublicUrl, ct));

    public const int MaxListed = 1000;

    /// <summary>The user's links, or all with PERM_LIST; newest <see cref="MaxListed"/>; expired ones left out (RULE-053).</summary>
    public static async Task<List<FileApiOutput>> ListForAsync(QhubDbContext db, User user, DateTimeOffset now, string publicUrl, CancellationToken ct)
    {
        var links = db.Links.AsNoTracking().Where(l =>
            (l.State == LinkState.Live && (l.ExpireAt == null || l.ExpireAt >= now) && (l.DownloadsRemaining == null || l.DownloadsRemaining > 0))
            || (l.State == LinkState.PendingDeletion && l.DeleteAt > now)
            || (l.State == LinkState.Reserved && l.ReservedUntil > now));
        if (!user.Permissions.HasFlag(UserPermissions.List)) links = links.Where(l => l.OwnerId == user.Id);
        var rows = await links.OrderByDescending(l => l.UploadedAt ?? l.ReservedUntil).ThenByDescending(l => l.Id).Take(MaxListed)
            .GroupJoin(db.StoredContents, l => l.ContentId, c => c.Id, (l, c) => new { l, c })
            .SelectMany(x => x.c.DefaultIfEmpty(), (x, c) => new { x.l, c })
            .ToListAsync(ct);
        return rows.Select(r => FileApiOutput.From(r.l, r.c, publicUrl)).ToList();
    }

    static async Task<IResult> ListOneAsync(string id, HttpContext http, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var link = await ServableAsync(db, id, time, ct);
        if (link is null) return ApiError.NotFoundId("File not found");
        if (!http.Caller().Reaches(link, UserPermissions.List)) return ApiError.Forbidden("No permission to view file");
        return ApiError.Json(await OutputAsync(db, link, o, ct));
    }

    /// <summary>The QR code of the customer URL; a reserved link has one before its document (RULE-107).</summary>
    static async Task<IResult> QrAsync(string id, HttpContext http, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var link = await db.Links.AsNoTracking().FirstOrDefaultAsync(l => l.Id == id &&
            ((l.State == LinkState.Reserved && l.ReservedUntil > now) || (l.State == LinkState.Live && (l.ExpireAt == null || l.ExpireAt >= now))), ct);
        if (link is null) return ApiError.NotFoundId("File not found");
        if (!http.Caller().Reaches(link, UserPermissions.List)) return ApiError.Forbidden("No permission to view file");
        // shortcut: no logo in the middle of the code yet (legacy custom/favicon.png overlay); add with the branding work.
        using var data = QRCodeGenerator.GenerateQrCode(o.Value.PublicUrl + "d?id=" + link.Id, QRCodeGenerator.ECCLevel.M);
        http.Response.Headers.CacheControl = "no-store";
        return Results.File(new PngByteQRCode(data).GetGraphic(8), "image/png");
    }

    static async Task<IResult> AddAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var (form, failure) = await ReadUploadAsync(http, o.Value, ct);
        if (failure is not null) return failure;
        return await StoreUploadAsync(http, docs, db, time, o, form!, reserved: null, ct);
    }

    static async Task<IResult> ReserveAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var link = await docs.ReserveAsync(http.Caller().User.Id, ct);
        return ApiError.Json(FileApiOutput.From(link, null, o.Value.PublicUrl).AsResult());
    }

    /// <summary>Fills a reserved link with its document (RULE-122): the owner only, once, before the reservation ends.</summary>
    static async Task<IResult> ContentAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("id", required: true);
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var (form, failure) = await ReadUploadAsync(http, o.Value, ct);
        if (failure is not null) return failure;

        var now = time.GetUtcNow();
        var link = await db.Links.FirstOrDefaultAsync(l => l.Id == id && (l.State == LinkState.Live || (l.State == LinkState.Reserved && l.ReservedUntil > now)), ct);
        if (link is null) return ApiError.NotFoundId("Invalid id provided.");
        if (link.OwnerId != http.Caller().User.Id) return ApiError.Forbidden("No permission to fill this link");
        if (link.State != LinkState.Reserved) return ApiError.Of(StatusCodes.Status409Conflict, ApiError.Unspecified, "The link already has a document");
        return await StoreUploadAsync(http, docs, db, time, o, form!, link, ct);
    }

    static async Task<IResult> StoreUploadAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o,
        IFormCollection form, Link? reserved, CancellationToken ct)
    {
        var values = ApiRequest.FromForm(form);
        var parameters = UploadParameters.Parse(values, time.GetUtcNow());
        if (parameters is null) return ApiError.BadInput(values.Error!);
        if (form.Files.GetFile("file") is not { } file) return ApiError.BadInput("http: no such file");
        try
        {
            await using var upload = file.OpenReadStream();
            var link = await docs.StoreAsync(http.Caller().User.Id, upload, file.FileName, file.ContentType, parameters, reserved, ct);
            return ApiError.Json((await OutputAsync(db, link, o, ct)).AsResult());
        }
        catch (UploadTooLargeException)
        {
            return ApiError.BadInput("upload limit exceeded", ApiError.FileTooLarge);
        }
    }

    /// <summary>Reads a multipart upload, refusing it early when it is over <c>QHUB_MAX_FILESIZE</c>.</summary>
    internal static async Task<(IFormCollection? Form, IResult? Failure)> ReadUploadAsync(HttpContext http, QhubOptions o, CancellationToken ct)
    {
        var limit = o.MaxFileSizeMb * 1024L * 1024L + 1024 * 1024; // the file plus the form fields
        if (http.Request.ContentLength > limit) return (null, ApiError.BadInput("upload limit exceeded", ApiError.FileTooLarge));
        if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } size) size.MaxRequestBodySize = limit;
        if (!http.Request.HasFormContentType) return (null, ApiError.BadInput("request Content-Type isn't multipart/form-data"));
        try
        {
            var form = await http.Request.ReadFormAsync(new FormOptions { MultipartBodyLengthLimit = limit }, ct);
            return (form, null);
        }
        catch (Exception e) when (e is InvalidDataException or BadHttpRequestException)
        {
            return (null, ApiError.BadInput(e.Message));
        }
    }

    /// <summary>A duplicate needs DOWNLOAD on the key, and List plus Edit for another user's link; it is audited (RULE-057 corrected, RULE-062).</summary>
    static async Task<IResult> DuplicateAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("id", required: true);
        var downloads = request.Int("allowedDownloads");
        var days = request.Int("expiryDays");
        var keepCode = request.Bool("originalPassword");
        var code = request.Has("password") ? request.Text("password") ?? "" : null;
        var name = request.Has("filename") ? request.Text("filename", base64: true) ?? "" : null;
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        if (downloads < 0 || days < 0) return ApiError.BadInput("allowedDownloads and expiryDays must not be negative", ApiError.CannotParse);
        if (keepCode) code = null;
        if (code is not null && !AccessCodes.IsValid(code))
            return ApiError.BadInput("password must not be empty: a document's code can be changed, but not removed. " + AccessCodes.InvalidMessage, ApiError.CannotParse);

        var link = await ServableAsync(db, id!, time, ct);
        if (link is null) return ApiError.NotFoundId("Invalid id provided.");
        var caller = http.Caller();
        if (!caller.KeyHas(ApiPermissions.Download) || !caller.Reaches(link, UserPermissions.List | UserPermissions.Edit))
            return ApiError.Forbidden("No permission to duplicate this file");
        var copy = await docs.DuplicateAsync(link, caller.User.Id, downloads, days, code, name, ct);
        return ApiError.Json(await OutputAsync(db, copy, o, ct));
    }

    static async Task<IResult> ChangeOwnerAsync(HttpContext http, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("id", required: true);
        var newOwner = request.Int("newOwner", required: true);
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var link = await ServableAsync(db, id!, time, ct, tracked: true);
        if (link is null) return ApiError.NotFoundId("Invalid id provided.");
        if (!http.Caller().Has(UserPermissions.Edit)) return ApiError.Forbidden("No permission to edit this file");
        if (!await db.Users.AnyAsync(u => u.Id == newOwner, ct)) return ApiError.BadInput("User does not exist", ApiError.NotFound);
        link.OwnerId = newOwner!.Value;
        Audit.AuditLog.Audit(db, time.GetUtcNow(), http.Caller().User.Id, "ChangeOwner", link.Id, $"{link.FileName}, ID {link.Id}, owner changed to user #{newOwner}");
        await db.SaveChangesAsync(ct);
        return ApiError.Json(await OutputAsync(db, link, o, ct));
    }

    /// <summary>Edit (RULE-046, RULE-048 and RULE-120 corrected): live links only, ownership or PERM_EDIT, validated values.</summary>
    static async Task<IResult> ModifyAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("id", required: true);
        var downloads = request.Int("allowedDownloads");
        var expiry = request.Long("expiryTimestamp");
        var code = request.Has("password") ? request.Text("password") ?? "" : null;
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        if (downloads < 0 || expiry < 0) return ApiError.BadInput("allowedDownloads and expiryTimestamp must not be negative", ApiError.CannotParse);
        if (code is not null && !AccessCodes.IsValid(code))
            return ApiError.BadInput("password must not be empty: a document's code can be changed, but not removed. " + AccessCodes.InvalidMessage, ApiError.CannotParse);

        var link = await ServableAsync(db, id!, time, ct, tracked: true);
        if (link is null) return ApiError.NotFoundId();
        if (!http.Caller().Reaches(link, UserPermissions.Edit)) return ApiError.Forbidden("No permission to edit file.");
        await docs.ModifyAsync(link, http.Caller().User.Id, downloads, expiry, code, ct);
        return ApiError.Json(await OutputAsync(db, link, o, ct));
    }

    /// <summary>Replace needs rights on both links (RULE-058) and keeps the link and code (RULE-106 corrected).</summary>
    static async Task<IResult> ReplaceAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("id", required: true);
        var sourceId = request.Text("idNewContent", required: true);
        var deleteSource = request.Bool("deleteNewFile");
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var caller = http.Caller();
        var target = await ServableAsync(db, id!, time, ct, tracked: true);
        if (target is null) return ApiError.NotFoundId("Invalid id provided.");
        if (!caller.Reaches(target, UserPermissions.ReplaceOther)) return ApiError.Forbidden("No permission to replace this file");
        var source = await ServableAsync(db, sourceId!, time, ct);
        if (source is null) return ApiError.NotFoundId("Invalid id provided.");
        if (!caller.Reaches(source, UserPermissions.List)) return ApiError.Forbidden("No permission to duplicate this file");
        if (deleteSource && (!caller.KeyHas(ApiPermissions.Delete) || !caller.Reaches(source, UserPermissions.Delete)))
            return ApiError.Forbidden("No permission to delete original file");
        if (source.Id == target.Id) return ApiError.BadInput("A file cannot replace itself", ApiError.InvalidUserInput);
        await docs.ReplaceAsync(target, source, deleteSource, caller.User.Id, ct);
        return ApiError.Json(await OutputAsync(db, target, o, ct));
    }

    /// <summary>Ownership or PERM_DELETE; now, or hidden and deleted after the delay (RULE-051, RULE-011, RULE-112, RULE-113).</summary>
    static async Task<IResult> DeleteAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("id", required: true);
        var delay = request.Int("delay") ?? 0;
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        if (delay < 0) return ApiError.BadInput("delay must not be negative", ApiError.CannotParse);
        var link = await db.Links.FirstOrDefaultAsync(l => l.Id == id, ct);
        if (link is null) return ApiError.NotFoundId();
        if (!http.Caller().Reaches(link, UserPermissions.Delete)) return ApiError.Forbidden("No permission to delete this file");
        await docs.DeleteAsync(link, http.Caller().User.Id, TimeSpan.FromSeconds(delay), ct);
        return Results.Ok();
    }

    static async Task<IResult> RestoreAsync(HttpContext http, Documents.Documents docs, QhubDbContext db, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("id", required: true);
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        const string gone = "Invalid file ID provided or file has already been deleted.";
        var link = await db.Links.FirstOrDefaultAsync(l => l.Id == id, ct);
        if (link is null) return ApiError.NotFoundId(gone);
        if (!http.Caller().Reaches(link, UserPermissions.Delete)) return ApiError.Forbidden("No permission to restore this file");
        if (link.State != LinkState.PendingDeletion)
            return ApiError.BadInput("The file is not scheduled for deletion, so there is nothing to restore", ApiError.InvalidUserInput);
        if (!await docs.RestoreAsync(link, http.Caller().User.Id, ct)) return ApiError.NotFoundId(gone);
        return ApiError.Json((await OutputAsync(db, link, o, ct)).AsResult());
    }

    /// <summary>API download: PERM_DOWNLOAD, ownership or PERM_LIST, no access code; counted only with increaseCounter (RULE-054).</summary>
    static async Task<IResult> DownloadAsync(string id, HttpContext http, QhubDbContext db, ContentStore store, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var count = request.Bool("increaseCounter");
        var presign = request.Bool("presignUrl");
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var link = await ServableAsync(db, id, time, ct);
        if (link is null) return ApiError.NotFoundId("file not found");
        if (!http.Caller().Reaches(link, UserPermissions.List)) return ApiError.Forbidden("no permission to download file");
        if (presign) return await Admin.AdminEndpoints.GrantAsync(db, http.Caller().User.Id, [link.Id], null, time, o.Value, ct);
        var content = await db.StoredContents.AsNoTracking().SingleAsync(c => c.Id == link.ContentId, ct);
        var source = await store.OpenAsync(content, link.FileName, redirectAllowed: true, ct);
        if (source is null) return ApiError.NotFoundId("file not found");
        if (count && !await CountAsync(db, link.Id, time.GetUtcNow(), ct))
        {
            source.Stream?.Dispose();
            return ApiError.NotFoundId("file not found");
        }
        return source.RedirectUrl is { } url
            ? Results.Redirect(url)
            : Results.File(source.Stream!, link.ContentType, link.FileName, enableRangeProcessing: source.Stream!.CanSeek);
    }

    /// <summary>Several links as one ZIP; increaseCounter counts each member (RULE-007 corrected, spec F5).</summary>
    static async Task<IResult> DownloadZipAsync(HttpContext http, QhubDbContext db, ContentStore store, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var ids = request.Text("ids", required: true);
        var name = request.Text("filename", base64: true);
        var count = request.Bool("increaseCounter");
        var presign = request.Bool("presignUrl");
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var members = new List<(Link Link, StoredContent Content)>();
        foreach (var id in ids!.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Distinct().Order(StringComparer.Ordinal))
        {
            var link = await ServableAsync(db, id, time, ct);
            if (link is null) return ApiError.NotFoundId("file not found");
            if (!http.Caller().Reaches(link, UserPermissions.List)) return ApiError.Forbidden("no permission to download file");
            members.Add((link, await db.StoredContents.AsNoTracking().SingleAsync(c => c.Id == link.ContentId, ct)));
        }
        if (presign) return await Admin.AdminEndpoints.GrantAsync(db, http.Caller().User.Id, members.Select(m => m.Link.Id), name, time, o.Value, ct);
        if (count)
        {
            foreach (var (link, _) in members)
                if (!await CountAsync(db, link.Id, time.GetUtcNow(), ct)) return ApiError.NotFoundId("file not found");
        }

        var zipName = (string.IsNullOrWhiteSpace(name) ? "Qhub" : Documents.Documents.SanitiseFileName(name)) + ".zip";
        return Results.Stream(async output =>
        {
            using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (link, content) in members)
            {
                var entryName = link.FileName;
                for (var n = 2; !used.Add(entryName); n++) entryName = $"{Path.GetFileNameWithoutExtension(link.FileName)} ({n}){Path.GetExtension(link.FileName)}";
                var source = await store.OpenAsync(content, link.FileName, redirectAllowed: false, ct);
                if (source?.Stream is not { } stream) continue;
                await using (stream)
                await using (var entry = await zip.CreateEntry(entryName, CompressionLevel.Fastest).OpenAsync(ct))
                    await stream.CopyToAsync(entry, ct);
            }
        }, "application/zip", zipName);
    }

    /// <summary>One API download counted, never below 0.</summary>
    static async Task<bool> CountAsync(QhubDbContext db, string linkId, DateTimeOffset now, CancellationToken ct) =>
        await db.Links.Where(l => l.Id == linkId).Servable(now).ExecuteUpdateAsync(s => s
            .SetProperty(l => l.DownloadsRemaining, l => l.DownloadsRemaining - 1)
            .SetProperty(l => l.DownloadCount, l => l.DownloadCount + 1), ct) == 1;

    static async Task<IResult> ChunkAddAsync(HttpContext http, Chunks chunks, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var (form, failure) = await ReadUploadAsync(http, o.Value, ct);
        if (failure is not null) return failure;
        var values = ApiRequest.FromForm(form!);
        var result = await chunks.AddAsync(http, http.Caller().User.Id, values.Text("uuid"), values.Long("offset"), values.Long("filesize"),
            form!.Files.GetFile("file"), ct);
        return result ?? ApiError.Json(new { Result = "OK" });
    }

    static async Task<IResult> ChunkCompleteAsync(HttpContext http, Chunks chunks, TimeProvider time, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var uuid = request.Text("uuid", required: true);
        var fileName = request.Text("filename", required: true, base64: true);
        var size = request.Long("filesize", required: true);
        var contentType = request.Text("contenttype");
        var nonBlocking = request.Bool("nonblocking");
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var parameters = UploadParameters.Parse(request, time.GetUtcNow());
        if (parameters is null) return ApiError.BadInput(request.Error!, ApiError.CannotParse);
        return await chunks.CompleteAsync(http.Caller().User, uuid!, fileName!, size!.Value, contentType, parameters, nonBlocking, ct);
    }

    internal static Task<Link?> ServableAsync(QhubDbContext db, string id, TimeProvider time, CancellationToken ct, bool tracked = false)
    {
        var links = tracked ? db.Links : db.Links.AsNoTracking();
        return links.Where(l => l.Id == id).Servable(time.GetUtcNow()).FirstOrDefaultAsync(ct);
    }

    internal static async Task<FileApiOutput> OutputAsync(QhubDbContext db, Link link, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var content = link.ContentId is { } id ? await db.StoredContents.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct) : null;
        return FileApiOutput.From(link, content, o.Value.PublicUrl);
    }
}
