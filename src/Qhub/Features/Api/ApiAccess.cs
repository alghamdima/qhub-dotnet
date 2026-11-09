using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Security;

namespace Qhub.Features.Api;

/// <summary>The caller of an <c>/api</c> route: the key's owner and the key.</summary>
public sealed record ApiCaller(User User, ApiKey Key)
{
    public bool IsAdmin => User.Rank is UserRank.SuperAdmin or UserRank.Admin;
    public bool Has(UserPermissions permission) => (User.Permissions & permission) == permission;
    public bool KeyHas(ApiPermissions permission) => (Key.Permissions & permission) == permission;
    /// <summary>Owns the link, or holds the user permission that reaches other users' links.</summary>
    public bool Reaches(Link link, UserPermissions otherUsers) => link.OwnerId == User.Id || Has(otherUsers);
}

/// <summary>Legacy <c>errorcodes</c> values the admin JS and issuing systems read.</summary>
public static class ApiError
{
    public const int Unspecified = 0, InvalidUrl = 1, InvalidApiKey = 2, AdminOnly = 3, CannotParse = 4, NotFound = 5,
        NoPermission = 6, AlreadyExists = 7, InternalServer = 8, FileTooLarge = 9, InvalidUserInput = 10, ChunkTooSmall = 11,
        CannotAllocateFile = 13, ResourceCanNotBeEdited = 19;

    static readonly JsonSerializerOptions Legacy = new() { PropertyNamingPolicy = null };

    /// <summary><c>{"Result":"error","ErrorMessage","ErrorCode"}</c>.</summary>
    public static IResult Of(int status, int code, string message) =>
        TypedResults.Json(new { Result = "error", ErrorMessage = message, ErrorCode = code }, Legacy, statusCode: status);

    public static IResult NotFoundId(string message = "Invalid file ID provided.") => Of(StatusCodes.Status404NotFound, NotFound, message);
    public static IResult Forbidden(string message) => Of(StatusCodes.Status401Unauthorized, NoPermission, message);
    public static IResult BadInput(string message, int code = Unspecified) => Of(StatusCodes.Status400BadRequest, code, message);

    /// <summary>JSON with the legacy property names (PascalCase as declared).</summary>
    public static IResult Json(object value) => TypedResults.Json(value, Legacy);
}

/// <summary>Bearer API keys (RULE-047, RULE-055, RULE-056, RULE-121).</summary>
public static class ApiAccess
{
    /// <summary>The route needs a valid key holding <paramref name="permission"/>; <paramref name="adminOnly"/> also needs an admin owner.</summary>
    public static RouteHandlerBuilder Requires(this RouteHandlerBuilder route, ApiPermissions permission, bool adminOnly = false) =>
        route.AddEndpointFilter(async (context, next) =>
        {
            var http = context.HttpContext;
            var caller = await AuthenticateAsync(http, permission);
            if (caller is null)
            {
                await http.RequestServices.GetRequiredService<ClientThrottle>().WaitAsync(ThrottleKind.FailedApiKey, http);
                return ApiError.Of(StatusCodes.Status401Unauthorized, ApiError.InvalidApiKey, "Unauthorized");
            }
            var options = http.RequestServices.GetRequiredService<IOptions<QhubOptions>>().Value;
            if (caller.Key.IsSystemKey && caller.User.MustChangePassword && options.Auth.Contains("internal", StringComparison.OrdinalIgnoreCase))
                return ApiError.Of(StatusCodes.Status403Forbidden, ApiError.NoPermission, "Password change required");
            if (adminOnly && !caller.IsAdmin)
                return ApiError.Of(StatusCodes.Status401Unauthorized, ApiError.AdminOnly, "Unauthorized");
            if (!OwnerHolds(caller, permission))
                return ApiError.Of(StatusCodes.Status401Unauthorized, ApiError.NoPermission, "Unauthorized");
            http.Items[typeof(ApiCaller)] = caller;
            return await next(context);
        });

    public static ApiCaller Caller(this HttpContext http) => (ApiCaller)http.Items[typeof(ApiCaller)]!;

    public static byte[] HashSecret(string secret) => SHA256.HashData(Encoding.UTF8.GetBytes(secret));

    static async Task<ApiCaller?> AuthenticateAsync(HttpContext http, ApiPermissions permission)
    {
        var header = http.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || header.Length <= 7) return null;
        var hash = HashSecret(header[7..].Trim());
        var db = http.RequestServices.GetRequiredService<QhubDbContext>();
        var now = http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();

        var found = await db.ApiKeys.AsNoTracking()
            .Where(k => k.SecretHash == hash && (k.ExpiresAt == null || k.ExpiresAt > now))
            .Join(db.Users.AsNoTracking(), k => k.OwnerId, u => u.Id, (k, u) => new { Key = k, User = u })
            .FirstOrDefaultAsync(http.RequestAborted);
        if (found is null || (found.Key.Permissions & permission) != permission) return null;

        await db.ApiKeys.Where(k => k.Id == found.Key.Id).ExecuteUpdateAsync(s => s.SetProperty(k => k.LastUsed, now), http.RequestAborted);
        return new ApiCaller(found.User, found.Key);
    }

    /// <summary>A sensitive key permission works only while the owner still holds the matching user permission (RULE-056).</summary>
    static bool OwnerHolds(ApiCaller caller, ApiPermissions permission) => permission switch
    {
        ApiPermissions.ManageUsers => caller.Has(UserPermissions.Users),
        ApiPermissions.ManageLogs => caller.Has(UserPermissions.Logs),
        ApiPermissions.Replace => caller.Has(UserPermissions.Replace),
        _ => true,
    };
}
