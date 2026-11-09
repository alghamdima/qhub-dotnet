using Qhub.Features.Api;
using Qhub.Security;

namespace Qhub.Features.Uploads;

/// <summary>A new link's limits and code. Null limits are unlimited.</summary>
public sealed record UploadParameters(int? Downloads, DateTimeOffset? ExpireAt, string Code)
{
    // One place for the defaults (RULE-014/124 corrected, RULE-015, RULE-127).
    public const int DefaultDownloads = 1;
    public const int DefaultExpiryDays = 14;
    /// <summary>Longer than this counts as unlimited time (legacy cap).</summary>
    public const int MaxExpiryDays = 100_000;

    /// <summary>
    /// The one validator for every upload path: /files/add and /files/content (form fields), /chunk/complete and /uploadChunk
    /// (headers). <c>allowedDownloads=0</c> and <c>expiryDays=0</c> mean unlimited; <c>expiryMinutes</c> overrides the days and is
    /// always limited; negatives are refused; a code is required on every path (RULE-052, RULE-068).
    /// </summary>
    public static UploadParameters? Parse(ApiRequest values, DateTimeOffset now)
    {
        var downloads = values.Int("allowedDownloads") ?? DefaultDownloads;
        var days = values.Int("expiryDays") ?? DefaultExpiryDays;
        var minutes = values.Int("expiryMinutes");
        var code = values.Text("password");
        if (values.Error is not null) return null;

        if (downloads < 0 || days < 0)
        {
            values.Fail("allowedDownloads and expiryDays must not be negative");
            return null;
        }
        if (minutes is < 1)
        {
            values.Fail("expiryMinutes must be a positive number");
            return null;
        }
        if (!AccessCodes.IsValid(code))
        {
            values.Fail(AccessCodes.InvalidMessage);
            return null;
        }

        var unlimitedDownloads = downloads == 0 || values.Text("isUnlimitedDownload") == "true";
        var unlimitedTime = days == 0 || days > MaxExpiryDays || values.Text("isUnlimitedTime") == "true";
        DateTimeOffset? expireAt = minutes is { } m ? now.AddMinutes(m) : unlimitedTime ? null : now.AddDays(days);
        return new UploadParameters(unlimitedDownloads ? null : downloads, expireAt, code!);
    }
}
