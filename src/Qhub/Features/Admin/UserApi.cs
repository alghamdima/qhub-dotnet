using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Api;
using Qhub.Features.Audit;
using Qhub.Features.Identity;

namespace Qhub.Features.Admin;

/// <summary><c>/api/user/*</c> (RULE-050, 059, 060, 119, 123, 147).</summary>
public static class UserApi
{
    public static void MapUserApi(this RouteGroupBuilder api)
    {
        api.MapPost("/user/create", CreateAsync).Requires(ApiPermissions.ManageUsers);
        api.MapPut("/user/modify", ModifyAsync).Requires(ApiPermissions.ManageUsers);
        api.MapPut("/user/changeRank", ChangeRankAsync).Requires(ApiPermissions.ManageUsers);
        api.MapPut("/user/resetPassword", ResetPasswordAsync).Requires(ApiPermissions.ManageUsers);
        api.MapDelete("/user/delete", DeleteAsync).Requires(ApiPermissions.ManageUsers);
    }

    /// <summary>The legacy <c>User</c> JSON (openapi <c>NewUser</c>).</summary>
    public static object Output(User u) => new
    {
        id = u.Id,
        lastOnline = u.LastOnline?.ToUnixTimeSeconds() ?? 0,
        name = u.Name,
        permissions = (int)u.Permissions,
        userLevel = (int)u.Rank,
        resetPassword = u.MustChangePassword,
    };

    static async Task<IResult> CreateAsync(HttpContext http, QhubDbContext db, TimeProvider time, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var name = request.Text("username", required: true)?.Trim().ToLowerInvariant();
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        if (name!.Length is < 2 or > 128) return ApiError.BadInput("Invalid username provided.", ApiError.NoPermission);
        if (await db.Users.AnyAsync(u => u.Name == name, ct)) return ApiError.Of(StatusCodes.Status409Conflict, ApiError.AlreadyExists, "User already exists.");
        var user = new User { Name = name, Rank = UserRank.User, SecurityStamp = Passwords.NewSecurityStamp() };
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        db.Audit(time.GetUtcNow(), http.Caller().User.Id, "UserCreated", null, $"{user.Name} (#{user.Id}) was created");
        await db.SaveChangesAsync(ct);
        return ApiError.Json(Output(user));
    }

    /// <summary>Grant needs the editor to hold the permission (RULE-059); a revoke also strips the matching key permission (RULE-147).</summary>
    static async Task<IResult> ModifyAsync(HttpContext http, QhubDbContext db, TimeProvider time, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Int("userid", required: true);
        var permissionName = request.Text("userpermission", required: true)?.ToUpperInvariant();
        var modifier = request.Text("permissionModifier", required: true)?.ToUpperInvariant();
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        UserPermissions? permission = permissionName switch
        {
            "PERM_REPLACE" => UserPermissions.Replace,
            "PERM_LIST" => UserPermissions.List,
            "PERM_EDIT" => UserPermissions.Edit,
            "PERM_REPLACE_OTHER" => UserPermissions.ReplaceOther,
            "PERM_DELETE" => UserPermissions.Delete,
            "PERM_LOGS" => UserPermissions.Logs,
            "PERM_API" => UserPermissions.Api,
            "PERM_USERS" => UserPermissions.Users,
            _ => null,
        };
        if (permission is null) return ApiError.BadInput("invalid permission", ApiError.CannotParse);
        if (modifier is not ("GRANT" or "REVOKE")) return ApiError.BadInput("invalid permission modifier", ApiError.CannotParse);

        var editor = http.Caller();
        var (target, failure) = await EditableAsync(db, id!.Value, editor, ct);
        if (failure is not null) return failure;
        if (target!.Rank == UserRank.SuperAdmin) return CannotEdit("Cannot modify super admin");
        if (target.Id == editor.User.Id) return CannotEdit("Cannot modify yourself");
        if (modifier == "GRANT" && !editor.Has(permission.Value)) return ApiError.BadInput("Cannot grant rights the user does not have", ApiError.NoPermission);

        if (modifier == "GRANT") target.Permissions |= permission.Value;
        else
        {
            target.Permissions &= ~permission.Value;
            await StripKeyPermissionAsync(db, target.Id, permission.Value, ct);
        }
        db.Audit(time.GetUtcNow(), editor.User.Id, "UserEdited", null, $"{target.Name} (#{target.Id}) was modified");
        await db.SaveChangesAsync(ct);
        return Results.Ok();
    }

    /// <summary>Changing rank resets permissions: admin gets all, user gets none and loses the sensitive key permissions (RULE-060).</summary>
    static async Task<IResult> ChangeRankAsync(HttpContext http, QhubDbContext db, TimeProvider time, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Int("userid", required: true);
        var rankName = request.Text("newRank", required: true)?.ToLowerInvariant();
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        UserRank? rank = rankName switch { "admin" => UserRank.Admin, "user" => UserRank.User, _ => null };
        if (rank is null) return ApiError.BadInput("invalid rank", ApiError.CannotParse);

        var editor = http.Caller();
        var (target, failure) = await EditableAsync(db, id!.Value, editor, ct);
        if (failure is not null) return failure;
        if (target!.Id == editor.User.Id) return CannotEdit("Cannot modify yourself");
        if (target.Rank == UserRank.SuperAdmin) return CannotEdit("Cannot modify super admin");
        if (rank == UserRank.Admin && !editor.IsAdmin) return CannotEdit("Only admins can promote users to admin");

        target.Rank = rank.Value;
        if (rank == UserRank.Admin) target.Permissions = UserPermissions.All;
        else
        {
            target.Permissions = UserPermissions.None;
            foreach (var p in new[] { UserPermissions.Replace, UserPermissions.Users, UserPermissions.Logs })
                await StripKeyPermissionAsync(db, target.Id, p, ct);
        }
        db.Audit(time.GetUtcNow(), editor.User.Id, "UserEdited", null, $"{target.Name} (#{target.Id}) was modified");
        await db.SaveChangesAsync(ct);
        return Results.Ok();
    }

    /// <summary>
    /// The user must change the password at the next login; optionally a random one is set and returned once. Every session of the
    /// user ends (RULE-123). Only an admin may set a new password on an account that has one (SEC-005).
    /// </summary>
    static async Task<IResult> ResetPasswordAsync(HttpContext http, QhubDbContext db, Passwords passwords, TimeProvider time, IOptions<QhubOptions> o, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Int("userid", required: true);
        var generate = request.Bool("generateNewPassword");
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var editor = http.Caller();
        var (target, failure) = await EditableAsync(db, id!.Value, editor, ct);
        if (failure is not null) return failure;
        if (target!.Rank == UserRank.SuperAdmin) return CannotEdit("Cannot reset password of super admin");
        if (target.Id == editor.User.Id) return CannotEdit("Cannot reset password of yourself");
        if (generate && !editor.IsAdmin && target.PasswordHash.Length > 0)
            return ApiError.Forbidden("Only an admin can generate a new password for an account that has one");

        target.MustChangePassword = true;
        var password = "";
        if (generate)
        {
            password = Passwords.Random(o.Value.MinLengthPassword + 2);
            target.PasswordHash = passwords.Hash(target, password);
        }
        target.SecurityStamp = Passwords.NewSecurityStamp();
        db.Audit(time.GetUtcNow(), editor.User.Id, "PasswordReset", null, $"{target.Name} (#{target.Id}) had the password reset");
        await db.SaveChangesAsync(ct);
        return Results.Json(new { Result = "OK", password });
    }

    /// <summary>Deleting a user (RULE-119): the links are deleted (PERM_DELETE) or kept by the editor (PERM_LIST); keys go too.</summary>
    static async Task<IResult> DeleteAsync(HttpContext http, QhubDbContext db, Documents.Documents docs, TimeProvider time, CancellationToken ct)
    {
        var request = ApiRequest.FromHeaders(http.Request);
        var id = request.Int("userid", required: true);
        var deleteFiles = request.Bool("deleteFiles");
        if (request.Error is { } error) return ApiError.BadInput(error, ApiError.CannotParse);
        var editor = http.Caller();
        var (target, failure) = await EditableAsync(db, id!.Value, editor, ct);
        if (failure is not null) return failure;
        if (target!.Rank == UserRank.SuperAdmin) return CannotEdit("Cannot delete super admin");
        if (target.Id == editor.User.Id) return CannotEdit("Cannot delete yourself");
        if (!deleteFiles && !editor.Has(UserPermissions.List)) return ApiError.Forbidden("Keeping the files of a deleted user needs PERM_LIST");
        if (deleteFiles && !editor.Has(UserPermissions.Delete)) return ApiError.Forbidden("Deleting the files of a deleted user needs PERM_DELETE");

        db.Audit(time.GetUtcNow(), editor.User.Id, "UserDeleted", null, $"{target.Name} (#{target.Id}) was deleted");
        await db.SaveChangesAsync(ct);
        if (deleteFiles)
        {
            foreach (var linkId in await db.Links.Where(l => l.OwnerId == target.Id).Select(l => l.Id).ToListAsync(ct))
                await docs.DeleteLinkNowAsync(linkId, ct);
        }
        else
        {
            await db.Links.Where(l => l.OwnerId == target.Id).ExecuteUpdateAsync(s => s.SetProperty(l => l.OwnerId, editor.User.Id), ct);
        }
        await db.ApiKeys.Where(k => k.OwnerId == target.Id).ExecuteDeleteAsync(ct);
        await db.Users.Where(u => u.Id == target.Id).ExecuteDeleteAsync(ct);
        return Results.Ok();
    }

    /// <summary>Who may manage a given user (RULE-050).</summary>
    static async Task<(User? User, IResult? Failure)> EditableAsync(QhubDbContext db, int id, ApiCaller editor, CancellationToken ct)
    {
        var target = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (target is null) return (null, ApiError.NotFoundId("Invalid user id provided."));
        if (target.Rank == UserRank.Admin && !editor.IsAdmin) return (null, CannotEdit("Only admins can modify admins"));
        if (!editor.IsAdmin && target.Rank != UserRank.SuperAdmin && !editor.Has(target.Permissions))
            return (null, CannotEdit("Cannot modify users with permissions you do not have"));
        return (target, null);
    }

    static IResult CannotEdit(string message) => ApiError.BadInput(message, ApiError.ResourceCanNotBeEdited);

    /// <summary>A removed user permission takes the matching key permission from all the user's keys (RULE-147).</summary>
    static async Task StripKeyPermissionAsync(QhubDbContext db, int userId, UserPermissions removed, CancellationToken ct)
    {
        var keyPermission = removed switch
        {
            UserPermissions.Users => ApiPermissions.ManageUsers,
            UserPermissions.Replace => ApiPermissions.Replace,
            UserPermissions.Logs => ApiPermissions.ManageLogs,
            _ => ApiPermissions.None,
        };
        if (keyPermission == ApiPermissions.None) return;
        foreach (var key in await db.ApiKeys.Where(k => k.OwnerId == userId).ToListAsync(ct))
            key.Permissions &= ~keyPermission;
    }
}
