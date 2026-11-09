using System.Globalization;
using Microsoft.AspNetCore.StaticFiles;

namespace Qhub.Features.Branding;

/// <summary>
/// The operator's <c>custom/</c> folder (moved as-is): custom.css, public.js, admin.js, favicon.png, version.txt. Served
/// without directory listing (PLAN §5 #1).
/// </summary>
public sealed class Branding
{
    public string Folder { get; }
    public bool HasCss { get; }
    public bool HasPublicJs { get; }
    public bool HasAdminJs { get; }
    public string Version { get; }
    public byte[] Favicon { get; }

    public Branding(IWebHostEnvironment env)
    {
        Folder = Path.Combine(Directory.GetCurrentDirectory(), "custom");
        HasCss = File.Exists(Path.Combine(Folder, "custom.css"));
        HasPublicJs = File.Exists(Path.Combine(Folder, "public.js"));
        HasAdminJs = File.Exists(Path.Combine(Folder, "admin.js"));
        var versionFile = Path.Combine(Folder, "version.txt");
        Version = File.Exists(versionFile) && int.TryParse(File.ReadLines(versionFile).FirstOrDefault()?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)
            ? v.ToString(CultureInfo.InvariantCulture) : "0";
        var customIcon = Path.Combine(Folder, "favicon.png");
        Favicon = File.ReadAllBytes(File.Exists(customIcon) ? customIcon : Path.Combine(env.WebRootPath, "defaultFavicon.png"));
    }
}

public static class BrandingEndpoints
{
    public static void MapBranding(this IEndpointRouteBuilder app)
    {
        var types = new FileExtensionContentTypeProvider();
        // shortcut: every favicon size is the same 512 px PNG (browsers scale it); the legacy built scaled PNGs and an .ico.
        app.MapGet("/favicon{rest}", (string rest, Branding b, HttpContext http) =>
        {
            http.Response.Headers.CacheControl = "public, max-age=36000";
            return Results.File(b.Favicon, "image/png");
        });
        app.MapGet("/custom/{*path}", (string? path, Branding b, HttpContext http) =>
        {
            if (string.IsNullOrEmpty(path) || path.EndsWith('/')) return Results.NotFound();
            // The versioned names in the page markup map to the plain files.
            path = path == $"custom.v{b.Version}.css" ? "custom.css" : path == $"public.v{b.Version}.js" ? "public.js" : path == $"admin.v{b.Version}.js" ? "admin.js" : path;
            var root = Path.GetFullPath(b.Folder) + Path.DirectorySeparatorChar;
            var file = Path.GetFullPath(Path.Combine(root, path));
            if (!file.StartsWith(root, StringComparison.Ordinal) || !File.Exists(file)) return Results.NotFound();
            http.Response.Headers.CacheControl = "public, max-age=100800";
            return Results.File(file, types.TryGetContentType(file, out var type) ? type : "application/octet-stream");
        });
    }
}
