using System.Text.Encodings.Web;

namespace Qhub.Pages;

/// <summary>
/// Values written into inline JavaScript in the admin markup. Razor then HTML-encodes the result, so a file name with a quote
/// cannot leave its JS string (the legacy html/template escaped by context).
/// </summary>
public static class PageJs
{
    public static string Str(string? value) => JavaScriptEncoder.Default.Encode(value ?? "");
    public static string Bool(bool value) => value ? "true" : "false";
}
