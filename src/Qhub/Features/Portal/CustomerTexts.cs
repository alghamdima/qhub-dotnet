using System.Text.Json;

namespace Qhub.Features.Portal;

/// <summary>The language of a customer page: Arabic (RTL) when the browser prefers it over English, otherwise English.</summary>
public sealed record CustomerPage(string Lang, string Dir, IReadOnlyDictionary<string, string> T);

/// <summary>Every customer-facing text, from <c>customer_texts.json</c> (moved as-is).</summary>
public sealed class CustomerTexts(IWebHostEnvironment env)
{
    readonly Dictionary<string, Dictionary<string, string>> texts =
        JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(
            File.ReadAllText(Path.Combine(env.ContentRootPath, "customer_texts.json")))!;

    public CustomerPage For(HttpRequest request)
    {
        var preferred = request.GetTypedHeaders().AcceptLanguage
            .OrderByDescending(l => l.Quality ?? 1)
            .Select(l => l.Value.Value?.Split('-')[0].ToLowerInvariant())
            .FirstOrDefault(l => l is "ar" or "en");
        return preferred == "ar" ? new("ar", "rtl", texts["ar"]) : new("en", "ltr", texts["en"]);
    }
}
