using System.Globalization;
using System.Text;

namespace Qhub.Features.Api;

/// <summary>
/// Reads the legacy header parameters. The first problem is kept in <see cref="Error"/>; the caller answers 400 CannotParse with it.
/// </summary>
public sealed class ApiRequest(Func<string, string?> get)
{
    public string? Error { get; private set; }

    public static ApiRequest FromHeaders(HttpRequest request) =>
        new(name => request.Headers.TryGetValue(name, out var value) ? value.ToString() : null);

    public static ApiRequest FromForm(IFormCollection form) =>
        new(name => form.TryGetValue(name, out var value) ? value.ToString() : null);

    public bool Has(string name) => get(name) is not null;

    /// <summary>A text value; <c>base64:</c> values are decoded when <paramref name="base64"/> (legacy <c>supportBase64</c>).</summary>
    public string? Text(string name, bool required = false, bool base64 = false)
    {
        var value = get(name);
        if (string.IsNullOrEmpty(value))
        {
            if (required) Fail($"header {name} is required");
            return value;
        }
        if (base64 && value.StartsWith("base64:", StringComparison.Ordinal))
        {
            try { return Encoding.UTF8.GetString(Convert.FromBase64String(value[7..])); }
            catch (FormatException) { Fail($"header {name} is not valid base64"); return null; }
        }
        return value;
    }

    public long? Long(string name, bool required = false)
    {
        var value = Text(name, required);
        if (string.IsNullOrEmpty(value)) return null;
        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)) return number;
        Fail($"header {name} must be a number");
        return null;
    }

    public int? Int(string name, bool required = false)
    {
        var value = Long(name, required);
        if (value is null) return null;
        if (value is >= int.MinValue and <= int.MaxValue) return (int)value;
        Fail($"header {name} is out of range");
        return null;
    }

    public bool Bool(string name)
    {
        var value = Text(name);
        if (string.IsNullOrEmpty(value)) return false;
        if (bool.TryParse(value, out var flag)) return flag;
        Fail($"header {name} must be true or false");
        return false;
    }

    public void Fail(string message) => Error ??= message;
}
