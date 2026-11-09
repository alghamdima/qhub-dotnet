using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Api;
using Qhub.Features.Documents;
using Qhub.Features.Identity;

namespace Qhub.Pages;

/// <summary>The upload page and file list (legacy template html_admin).</summary>
public sealed class AdminModel(QhubDbContext db, TimeProvider time, IOptions<QhubOptions> options) : AdminPage
{
    public List<FileApiOutput> Items { get; private set; } = [];
    public bool IsFileListTruncated { get; private set; }
    public long TimeNow { get; private set; }
    public QhubOptions Settings => options.Value;

    public bool Has(UserPermissions p) => ActiveUser.Permissions.HasFlag(p);

    public async Task OnGetAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        TimeNow = now.ToUnixTimeSeconds();
        Items = await FileApi.ListForAsync(db, ActiveUser, now, options.Value.PublicUrl, ct);
        IsFileListTruncated = Items.Count == FileApi.MaxListed;
    }
}
