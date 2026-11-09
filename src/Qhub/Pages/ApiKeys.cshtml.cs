using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Identity;

namespace Qhub.Pages;

/// <summary>The API keys page (legacy template html_api): own keys, or all with PERM_API; temporary tokens are never listed.</summary>
public sealed class ApiKeysModel(QhubDbContext db, IOptions<QhubOptions> options) : AdminPage
{
    public sealed record Row(ApiKey Key, User Owner)
    {
        public bool Has(ApiPermissions p) => Key.Permissions.HasFlag(p);

        /// <summary>The CSS state of a permission icon; owner-bound permissions are unavailable when the owner lacks them.</summary>
        public string State(ApiPermissions p, UserPermissions? ownerNeeds = null) =>
            ownerNeeds is { } needed && !Owner.Permissions.HasFlag(needed) ? "perm-unavailable perm-nochange" : Has(p) ? "perm-granted" : "perm-notgranted";
    }

    public List<Row> Keys { get; private set; } = [];
    public bool CanManageAll => ActiveUser.Permissions.HasFlag(UserPermissions.Api);

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (options.Value.DisableApiMenu && ActiveUser.Rank is not (UserRank.SuperAdmin or UserRank.Admin)) return this.SeeOther("admin");
        var keys = db.ApiKeys.AsNoTracking().Where(k => !k.IsSystemKey);
        if (!CanManageAll) keys = keys.Where(k => k.OwnerId == ActiveUser.Id);
        Keys = (await keys.Join(db.Users.AsNoTracking(), k => k.OwnerId, u => u.Id, (k, u) => new { k, u }).ToListAsync(ct))
            .OrderByDescending(x => x.k.LastUsed).ThenBy(x => x.k.Id, StringComparer.Ordinal)
            .Select(x => new Row(x.k, x.u)).ToList();
        return Page();
    }
}
