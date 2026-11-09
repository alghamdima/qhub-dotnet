using Qhub.Data;
using Qhub.Domain;

namespace Qhub.Features.Audit;

public static class AuditLog
{
    /// <summary>Adds an audit entry; it is saved with the caller's next SaveChanges.</summary>
    public static void Audit(this QhubDbContext db, DateTimeOffset at, int? actorUserId, string action, string? linkId, string detail, string? clientIp = null) =>
        db.AuditEntries.Add(new AuditEntry
        {
            At = at,
            ActorUserId = actorUserId,
            Action = action,
            LinkId = linkId,
            Detail = detail.Length > 2000 ? detail[..2000] : detail,
            ClientIp = clientIp,
        });
}
