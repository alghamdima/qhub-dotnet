using System.IO.Compression;
using System.Net.ServerSentEvents;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Api;
using Qhub.Features.Identity;
using Qhub.Features.Storage;
using Qhub.Features.Uploads;

namespace Qhub.Features.Admin;

/// <summary>The session endpoints the admin pages call (spec §3.3).</summary>
public static class AdminEndpoints
{
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan GrantLifetime = TimeSpan.FromSeconds(30);

    public static void MapAdmin(this IEndpointRouteBuilder app)
    {
        // Kept as GET because the markup links to it; a cross-site logout does little harm.
        app.MapGet("/logout", async (HttpContext http) =>
        {
            await Sessions.SignOutAsync(http);
            http.Response.Headers.Location = "./login";
            return Results.StatusCode(StatusCodes.Status303SeeOther);
        });
        app.MapPost("/auth/token", TokenAsync).RequiresSession().DisableAntiforgery();
        app.MapPost("/uploadChunk", UploadChunkAsync).RequiresSession().DisableAntiforgery();
        app.MapGet("/uploadStatus", (HttpContext http, UploadStatusHub hub) =>
            TypedResults.ServerSentEvents(StatusEvents(hub, http.CurrentUser()!.Id, http.RequestAborted))).RequiresSession();
        app.MapGet("/downloadPresigned", DownloadPresignedAsync).RequiresSession();
    }

    /// <summary>A 5-minute system key for the admin JS, bounded by the user's own permissions (RULE-067).</summary>
    static async Task<IResult> TokenAsync(HttpContext http, QhubDbContext db, TimeProvider time)
    {
        var user = http.CurrentUser()!;
        if (ApiPermissionNames.Parse(http.Request.Headers["permission"].ToString()) is not { } permission)
            return Results.Text("Invalid permission", statusCode: StatusCodes.Status400BadRequest);
        foreach (var (needed, held, name) in new[]
        {
            (ApiPermissions.Replace, UserPermissions.Replace, "PERM_REPLACE"),
            (ApiPermissions.ManageUsers, UserPermissions.Users, "PERM_MANAGE_USERS"),
            (ApiPermissions.ManageLogs, UserPermissions.Logs, "PERM_MANAGE_LOGS"),
        })
        {
            if (permission.HasFlag(needed) && !user.Permissions.HasFlag(held))
                return Results.Text($"user does not have permission to generate a token with {name}", statusCode: StatusCodes.Status400BadRequest);
        }
        var secret = ApiPermissionNames.NewSecret();
        var expiry = time.GetUtcNow() + TokenLifetime;
        db.ApiKeys.Add(new ApiKey
        {
            Id = ApiPermissionNames.NewPublicId(),
            OwnerId = user.Id,
            SecretHash = ApiAccess.HashSecret(secret),
            FriendlyName = "Temporary Token",
            Permissions = permission,
            IsSystemKey = true,
            ExpiresAt = expiry,
        });
        await db.SaveChangesAsync(http.RequestAborted);
        return Results.Json(new { key = secret, expiry = expiry.ToUnixTimeSeconds() });
    }

    /// <summary>A chunk from the admin page's Dropzone (fields dzuuid, dzchunkbyteoffset, dztotalfilesize).</summary>
    static async Task<IResult> UploadChunkAsync(HttpContext http, Chunks chunks, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var (form, failure) = await FileApi.ReadUploadAsync(http, o.Value, ct);
        if (failure is not null) return failure;
        var values = ApiRequest.FromForm(form!);
        var result = await chunks.AddAsync(http, http.CurrentUser()!.Id, values.Text("dzuuid"), values.Long("dzchunkbyteoffset"),
            values.Long("dztotalfilesize"), form!.Files.GetFile("file"), ct);
        return result ?? Results.Json(new { result = "OK" });
    }

    /// <summary>The user's upload statuses (kept ones first), live events, a ping every 15 s; closed after 2 hours.</summary>
    static async IAsyncEnumerable<SseItem<string>> StatusEvents(UploadStatusHub hub, int userId, [EnumeratorCancellation] CancellationToken ct)
    {
        var (events, subscription) = hub.Subscribe(userId);
        using var _ = subscription;
        using var connection = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connection.CancelAfter(TimeSpan.FromHours(2));
        while (!connection.IsCancellationRequested)
        {
            var (closed, json) = await NextAsync(events, connection.Token);
            if (closed) yield break;
            yield return json is null ? new SseItem<string>("", "ping") : new SseItem<string>(json, "message");
        }
    }

    static async Task<(bool Closed, string? Json)> NextAsync(ChannelReader<string> events, CancellationToken connection)
    {
        using var ping = CancellationTokenSource.CreateLinkedTokenSource(connection);
        ping.CancelAfter(TimeSpan.FromSeconds(15));
        try { return (false, await events.ReadAsync(ping.Token)); }
        catch (OperationCanceledException) { return (connection.IsCancellationRequested, null); }
        catch (ChannelClosedException) { return (true, null); }
    }

    /// <summary>Creates a single-use, 30-second admin download link bound to the user (RULE-082).</summary>
    public static async Task<IResult> GrantAsync(QhubDbContext db, int userId, IEnumerable<string> linkIds, string? zipName, TimeProvider time, QhubOptions o, CancellationToken ct)
    {
        var id = RandomNumberGenerator.GetString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 60);
        db.DownloadGrants.Add(new DownloadGrant { Id = id, UserId = userId, LinkIds = string.Join(',', linkIds) + (zipName is null ? "" : "/" + zipName), ExpiresAt = time.GetUtcNow() + GrantLifetime });
        await db.SaveChangesAsync(ct);
        return ApiError.Json(new { Result = "OK", downloadUrl = o.PublicUrl + "downloadPresigned?key=" + id });
    }

    static async Task<IResult> DownloadPresignedAsync(string? key, HttpContext http, QhubDbContext db, ContentStore store, TimeProvider time, CancellationToken ct)
    {
        http.Response.Headers.CacheControl = "no-store, no-cache";
        var invalid = Results.Json(new { Result = "error", ErrorMessage = "presigned URL is invalid or has expired" }, statusCode: StatusCodes.Status400BadRequest);
        var now = time.GetUtcNow();
        var userId = http.CurrentUser()!.Id;
        var grant = key is null ? null : await db.DownloadGrants.AsNoTracking().FirstOrDefaultAsync(g => g.Id == key && g.UserId == userId && g.ExpiresAt > now, ct);
        if (grant is null) return invalid;
        // Single use: whoever deletes the row may use it.
        if (await db.DownloadGrants.Where(g => g.Id == grant.Id).ExecuteDeleteAsync(ct) == 0) return invalid;

        var slash = grant.LinkIds.IndexOf('/');
        var ids = (slash < 0 ? grant.LinkIds : grant.LinkIds[..slash]).Split(',');
        var members = new List<(Link Link, StoredContent Content)>();
        foreach (var id in ids)
        {
            var link = await db.Links.AsNoTracking().Where(l => l.Id == id).Servable(now).FirstOrDefaultAsync(ct);
            if (link is null) return Results.Json(new { Result = "error", ErrorMessage = "file not found" }, statusCode: StatusCodes.Status400BadRequest);
            members.Add((link, await db.StoredContents.AsNoTracking().SingleAsync(c => c.Id == link.ContentId, ct)));
        }
        if (members.Count == 1)
        {
            var (link, content) = members[0];
            var source = await store.OpenAsync(content, link.FileName, redirectAllowed: true, ct);
            if (source is null) return Results.NotFound();
            return source.RedirectUrl is { } url ? Results.Redirect(url) : Results.File(source.Stream!, link.ContentType, link.FileName, enableRangeProcessing: source.Stream!.CanSeek);
        }
        var zipName = (slash < 0 || slash == grant.LinkIds.Length - 1 ? "Qhub" : grant.LinkIds[(slash + 1)..]) + ".zip";
        return Results.Stream(async output =>
        {
            using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
            foreach (var (link, content) in members)
            {
                var source = await store.OpenAsync(content, link.FileName, redirectAllowed: false, ct);
                if (source?.Stream is not { } stream) continue;
                await using (stream)
                await using (var entry = await zip.CreateEntry(link.FileName, CompressionLevel.Fastest).OpenAsync(ct))
                    await stream.CopyToAsync(entry, ct);
            }
        }, "application/zip", zipName);
    }
}

/// <summary>The <c>PERM_*</c> strings the admin JS and issuing systems send (spec F9).</summary>
public static class ApiPermissionNames
{
    public static ApiPermissions? Parse(string? name) => name?.ToUpperInvariant() switch
    {
        "PERM_VIEW" => ApiPermissions.View,
        "PERM_UPLOAD" => ApiPermissions.Upload,
        "PERM_DELETE" => ApiPermissions.Delete,
        "PERM_API_MOD" => ApiPermissions.ApiManage,
        "PERM_EDIT" => ApiPermissions.Edit,
        "PERM_REPLACE" => ApiPermissions.Replace,
        "PERM_MANAGE_USERS" => ApiPermissions.ManageUsers,
        "PERM_MANAGE_LOGS" => ApiPermissions.ManageLogs,
        "PERM_DOWNLOAD" => ApiPermissions.Download,
        _ => null,
    };

    const string Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    /// <summary>30 characters, shown once (legacy <c>LengthApiKey</c>).</summary>
    public static string NewSecret() => RandomNumberGenerator.GetString(Alphabet, 30);
    /// <summary>35 characters (legacy <c>LengthPublicId</c>), used by the API keys page.</summary>
    public static string NewPublicId() => RandomNumberGenerator.GetString(Alphabet, 35);
}
