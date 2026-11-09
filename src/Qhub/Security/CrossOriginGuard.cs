namespace Qhub.Security;

/// <summary>
/// Rejects cross-site browser requests that change something (RULE-041, RULE-064 revised): <c>Sec-Fetch-Site</c>, or the
/// <c>Origin</c> host, must be this site. The SAML response and Bearer API calls are exempt; forms also carry antiforgery tokens.
/// </summary>
public sealed class CrossOriginGuard(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext http)
    {
        var request = http.Request;
        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method) || HttpMethods.IsOptions(request.Method)
            || request.Path.StartsWithSegments("/saml-acs")
            || request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return next(http);

        var site = request.Headers["Sec-Fetch-Site"].ToString();
        var crossSite = site.Length > 0
            ? site is not ("same-origin" or "none")
            : Uri.TryCreate(request.Headers.Origin.ToString(), UriKind.Absolute, out var origin)
              && !string.Equals(origin.Authority, request.Host.Value, StringComparison.OrdinalIgnoreCase);
        if (!crossSite) return next(http);

        http.Response.StatusCode = StatusCodes.Status403Forbidden;
        return http.Response.WriteAsync("cross-origin request detected");
    }
}
