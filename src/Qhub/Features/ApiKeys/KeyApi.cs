using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Admin;
using Qhub.Features.Api;

namespace Qhub.Features.ApiKeys;

/// <summary><c>/api/auth/*</c>: per-user keys, stored hashed, bounded by the owner's permissions (RULE-005, RULE-049).</summary>
public static class KeyApi
{
    public static void MapKeyApi(this RouteGroupBuilder api)
    {
        api.MapPost("/auth/create", CreateAsync).Requires(ApiPermissions.ApiManage);
        api.MapPut("/auth/friendlyname", RenameAsync).Requires(ApiPermissions.ApiManage);
        api.MapPut("/auth/modify", ModifyAsync).Requires(ApiPermissions.ApiManage);
        api.MapDelete("/auth/delete", DeleteAsync).Requires(ApiPermissions.ApiManage);
    }

    /// <summary>A new key: basic permissions (VIEW, UPLOAD, DELETE, EDIT) or none; the secret is returned once (RULE-005).</summary>
    static async Task<IResult> CreateAsync(HttpContext http, QhubDbContext db, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var name = request.Text("friendlyName");
        var basic = request.Bool("basicPermissions");
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var caller = http.Caller();
        if (o.Value.DisableApiMenu && !caller.IsAdmin)
            return ApiError.Of(StatusCodes.Status403Forbidden, ApiError.NoPermission, "User API keys are disabled for this instance");

        var secret = ApiPermissionNames.NewSecret();
        var key = new ApiKey
        {
            Id = ApiPermissionNames.NewPublicId(),
            OwnerId = caller.User.Id,
            SecretHash = ApiAccess.HashSecret(secret),
            FriendlyName = string.IsNullOrEmpty(name) ? "Unnamed key" : name,
            Permissions = basic ? ApiPermissions.Basic : ApiPermissions.None,
        };
        db.ApiKeys.Add(key);
        await db.SaveChangesAsync(ct);
        return ApiError.Json(new { Result = "OK", Id = secret, PublicId = key.Id });
    }

    static async Task<IResult> RenameAsync(HttpContext http, QhubDbContext db, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("targetKey", required: true);
        var name = request.Text("friendlyName", required: true);
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var (key, failure) = await EditableAsync(http, db, id!, "No permission to edit this API key", ct);
        if (failure is not null) return failure;
        key!.FriendlyName = string.IsNullOrEmpty(name) ? "Unnamed key" : name;
        await db.SaveChangesAsync(ct);
        return Results.Ok();
    }

    /// <summary>Grant or revoke; REPLACE, MANAGE_USERS and MANAGE_LOGS need the key owner to hold the user permission (RULE-049).</summary>
    static async Task<IResult> ModifyAsync(HttpContext http, QhubDbContext db, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("targetKey", required: true);
        var permissionName = request.Text("permission", required: true);
        var modifier = request.Text("permissionModifier", required: true)?.ToUpperInvariant();
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        if (ApiPermissionNames.Parse(permissionName) is not { } permission) return ApiError.BadInput("invalid permission", ApiError.CannotParse);
        if (modifier is not ("GRANT" or "REVOKE")) return ApiError.BadInput("invalid permission modifier", ApiError.CannotParse);

        var (key, failure) = await EditableAsync(http, db, id!, "No permission to delete this API key", ct);
        if (failure is not null) return failure;
        var owner = await db.Users.AsNoTracking().SingleAsync(u => u.Id == key!.OwnerId, ct);
        var needed = permission switch
        {
            ApiPermissions.Replace => UserPermissions.Replace,
            ApiPermissions.ManageUsers => UserPermissions.Users,
            ApiPermissions.ManageLogs => UserPermissions.Logs,
            _ => UserPermissions.None,
        };
        if (!owner.Permissions.HasFlag(needed))
            return ApiError.Forbidden("Insufficient user permission for owner to set this API permission");
        key!.Permissions = modifier == "GRANT" ? key.Permissions | permission : key.Permissions & ~permission;
        await db.SaveChangesAsync(ct);
        return Results.Ok();
    }

    static async Task<IResult> DeleteAsync(HttpContext http, QhubDbContext db, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Text("targetKey", required: true);
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var (key, failure) = await EditableAsync(http, db, id!, "No permission to delete this API key", ct);
        if (failure is not null) return failure;
        db.ApiKeys.Remove(key!);
        await db.SaveChangesAsync(ct);
        return Results.Ok();
    }

    /// <summary>A user key (not a temporary token) the caller owns, or any with PERM_API.</summary>
    static async Task<(ApiKey? Key, IResult? Failure)> EditableAsync(HttpContext http, QhubDbContext db, string id, string forbidden, CancellationToken ct)
    {
        var key = await db.ApiKeys.FirstOrDefaultAsync(k => k.Id == id && !k.IsSystemKey, ct);
        if (key is null) return (null, ApiError.NotFoundId("Invalid key ID provided."));
        var caller = http.Caller();
        if (key.OwnerId != caller.User.Id && !caller.Has(UserPermissions.Api)) return (null, ApiError.Forbidden(forbidden));
        return (key, null);
    }
}
