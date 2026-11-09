using Qhub.Domain;

namespace Qhub.Features.Documents;

/// <summary>The legacy <c>FileApiOutput</c> (openapi <c>File</c>); the admin JS reads these exact names.</summary>
public sealed record FileApiOutput(
    string Id,
    string Name,
    string Size,
    string ContentType,
    string ExpireAtString,
    string UrlDownload,
    long UploadDate,
    long ExpireAt,
    long SizeBytes,
    int DownloadsRemaining,
    int DownloadCount,
    bool UnlimitedDownloads,
    bool UnlimitedTime,
    bool IsEncrypted,
    bool IsPasswordProtected,
    bool IsSavedOnLocalStorage,
    bool IsPendingDeletion,
    int UploaderId)
{
    public static FileApiOutput From(Link link, StoredContent? content, string publicUrl)
    {
        var expireAt = link.State == LinkState.Reserved ? link.ReservedUntil : link.ExpireAt;
        return new FileApiOutput(
            link.Id,
            link.FileName,
            LinkRules.FormatSize(content?.SizeBytes ?? 0),
            link.ContentType,
            (expireAt ?? DateTimeOffset.UnixEpoch).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture),
            publicUrl + "d?id=" + link.Id,
            link.UploadedAt?.ToUnixTimeSeconds() ?? 0,
            expireAt?.ToUnixTimeSeconds() ?? 0,
            content?.SizeBytes ?? 0,
            link.DownloadsRemaining ?? 0,
            link.DownloadCount,
            link.DownloadsRemaining is null,
            expireAt is null,
            content?.Encrypted ?? false,
            link.AccessCodeMac is not null,
            content is null || content.StoreKind == StoreKind.Local,
            link.State == LinkState.PendingDeletion,
            link.OwnerId);
    }

    /// <summary><c>{"Result":"OK","FileInfo":…}</c>.</summary>
    public object AsResult() => new { Result = "OK", FileInfo = this };
}
