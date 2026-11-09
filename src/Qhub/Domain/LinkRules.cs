using System.Security.Cryptography;

namespace Qhub.Domain;

public static class LinkRules
{
    const string IdAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /// <summary>A random link ID of <c>QHUB_LENGTH_ID</c> characters, at least 5 (RULE-004). Inserts never overwrite: the ID is the primary key.</summary>
    public static string NewId(int length) => RandomNumberGenerator.GetString(IdAlphabet, Math.Max(length, 5));

    /// <summary>
    /// Links a customer may open (RULE-108, RULE-010): live, with content, not past <see cref="Link.ExpireAt"/>
    /// (still valid at that exact instant) and with downloads left.
    /// </summary>
    public static IQueryable<Link> Servable(this IQueryable<Link> links, DateTimeOffset now) =>
        links.Where(l => l.State == LinkState.Live && l.ContentId != null
            && (l.ExpireAt == null || l.ExpireAt >= now)
            && (l.DownloadsRemaining == null || l.DownloadsRemaining > 0));

    /// <summary>The size as the download page shows it, e.g. "1.2 MB" (1024-based, as the legacy page).</summary>
    public static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double size = bytes;
        var unit = 0;
        for (size /= 1024; size >= 1024 && unit < 5; size /= 1024) unit++;
        return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{size:0.0} {"kMGTPE"[unit]}B");
    }
}
