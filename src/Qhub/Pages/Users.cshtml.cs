using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Identity;

namespace Qhub.Pages;

/// <summary>The users page (legacy template html_users); needs PERM_USERS.</summary>
public sealed class UsersModel(QhubDbContext db, TimeProvider time, IOptions<QhubOptions> options) : AdminPage
{
    public sealed record Row(User User, int UploadCount);

    public List<Row> Users { get; private set; } = [];
    public bool IsInternalAuth => options.Value.IsInternalAuth();
    public bool IsAdmin => ActiveUser.Rank is UserRank.SuperAdmin or UserRank.Admin;

    public bool Has(UserPermissions p) => ActiveUser.Permissions.HasFlag(p);

    /// <summary>A permission icon's classes: granted or not, and locked for the super admin, oneself, or a permission the editor lacks.</summary>
    public string State(User u, UserPermissions p) =>
        (u.Permissions.HasFlag(p) ? "perm-granted" : "perm-notgranted")
        + (!Has(p) || u.Rank == UserRank.SuperAdmin || u.Id == ActiveUser.Id ? " perm-nochange" : "");

    public static string Level(User u) => u.Rank switch
    {
        UserRank.SuperAdmin => "Super Admin",
        UserRank.Admin => "Admin",
        UserRank.User => "User",
        _ => "Invalid",
    };

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!Has(UserPermissions.Users)) return this.SeeOther("admin");
        var counts = await db.Links.GroupBy(l => l.OwnerId).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        var now = time.GetUtcNow();
        Users = (await db.Users.AsNoTracking().OrderBy(u => u.Id).ToListAsync(ct))
            .Select(u => new Row(u.Id == ActiveUser.Id ? CopyOnline(u, now) : u, counts.GetValueOrDefault(u.Id))).ToList();
        return Page();
    }

    static User CopyOnline(User u, DateTimeOffset now)
    {
        u.LastOnline = now;
        return u;
    }
}
