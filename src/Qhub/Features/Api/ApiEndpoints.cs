using System.Text.Json;
using Qhub.Features.Admin;
using Qhub.Features.ApiKeys;
using Qhub.Features.Audit;

namespace Qhub.Features.Api;

/// <summary>
/// Every operation of <c>wwwroot/apidocumentation/openapi.json</c> under <c>/api</c>, with its HTTP method enforced
/// (spec §3.1 F1). Phases 2–3 replace each stub with the feature service call.
/// </summary>
public static class ApiEndpoints
{
    /// <summary>Legacy <c>errorcodes</c> value the admin JS reads.</summary>
    const int UnspecifiedError = 0;

    static readonly JsonSerializerOptions LegacyJson = new(JsonSerializerDefaults.Web) { PropertyNamingPolicy = null };

    public static void MapApi(this IEndpointRouteBuilder app)
    {
        // Bearer keys, not cookies: no antiforgery; responses are never cached.
        var api = app.MapGroup("/api").DisableAntiforgery();
        api.AddEndpointFilter(async (context, next) =>
        {
            context.HttpContext.Response.Headers.CacheControl = "no-store";
            return await next(context);
        });
        api.MapFileApi();
        api.MapKeyApi();
        api.MapUserApi();
        api.MapLogApi();
    }

    /// <summary>The legacy error shape <c>{"Result":"error","ErrorMessage","ErrorCode"}</c>.</summary>
    internal static IResult LegacyError(int status, string message, int code) =>
        TypedResults.Json(new LegacyApiError("error", message, code), LegacyJson, statusCode: status);

    sealed record LegacyApiError(string Result, string ErrorMessage, int ErrorCode);
}
