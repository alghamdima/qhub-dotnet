using Microsoft.AspNetCore.Mvc;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Audit;
using Qhub.Features.Identity;

namespace Qhub.Pages;

/// <summary>The status and logs page (legacy template html_logs); needs PERM_LOGS.</summary>
public sealed class LogsModel(QhubDbContext db, ServerStats stats, TimeProvider time) : AdminPage
{
    public ServerStatus Status { get; private set; } = null!;
    public bool IsAdmin => ActiveUser.Rank is UserRank.SuperAdmin or UserRank.Admin;

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!ActiveUser.Permissions.HasFlag(UserPermissions.Logs)) return this.SeeOther("admin");
        Status = await stats.SnapshotAsync(db, time.GetUtcNow(), ct);
        return Page();
    }
}
