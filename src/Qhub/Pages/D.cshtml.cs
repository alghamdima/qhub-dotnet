using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Domain;
using Qhub.Features.Portal;
using Qhub.Security;

namespace Qhub.Pages;

/// <summary>The customer page <c>/d?id=</c> (RULE-117, RULE-044, RULE-128, RULE-146, RULE-150).</summary>
public sealed class DModel(QhubDbContext db, AccessCodes codes, CodeAttempts attempts, Passes passes, ClientThrottle throttle,
    CustomerTexts texts, TimeProvider time, IOptions<QhubOptions> options) : PageModel
{
    public Link Link { get; private set; } = null!;
    public string Size { get; private set; } = "";
    public CustomerPage Customer { get; private set; } = null!;
    public bool IsPasswordView { get; private set; }
    public bool IsLocked { get; private set; }
    public bool IsFailedLogin { get; private set; }
    public int AttemptsLeft { get; private set; }

    public async Task<IActionResult> OnGetAsync(string? id, CancellationToken ct)
    {
        if (await LoadAsync(id, ct) is { } failure) return failure;
        IsPasswordView = passes.Validate(Request, Link) is null;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? id, string? password, CancellationToken ct)
    {
        if (await LoadAsync(id, ct) is { } failure) return failure;
        if (passes.Validate(Request, Link) is not null) return Page();
        IsPasswordView = true;
        if (string.IsNullOrEmpty(password)) return Page();

        if (!await throttle.WaitAsync(ThrottleKind.CodeAttempt, HttpContext)) return StatusCode(StatusCodes.Status429TooManyRequests);
        if (await attempts.TryTakeAsync(Link.Id, ct) is not { } attempt)
        {
            IsLocked = true; // no check and no new count while locked
            return Page();
        }
        if (codes.Verify(password, Link.AccessCodeMac))
        {
            await attempts.ResetAsync(Link.Id, ct);
            passes.Issue(Response, Link);
            Response.Headers.Location = "./d?id=" + Uri.EscapeDataString(Link.Id);
            return StatusCode(StatusCodes.Status303SeeOther); // no form data to resend on refresh
        }

        AttemptsLeft = CodeAttempts.MaxAttempts - attempt;
        IsLocked = AttemptsLeft == 0;
        IsFailedLogin = !IsLocked;
        // A security event: the IP is always kept, as in the legacy log.
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        db.AuditEntries.Add(new AuditEntry
        {
            At = time.GetUtcNow(),
            Action = "WrongCode",
            LinkId = Link.Id,
            Detail = $"Wrong password for file {Link.Id} by IP {ip}" + (IsLocked ? ", file locked after too many wrong passwords" : ""),
            ClientIp = ip,
        });
        await db.SaveChangesAsync(ct);
        return Page();
    }

    async Task<IActionResult?> LoadAsync(string? id, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store, no-cache";
        Customer = texts.For(Request);
        ViewData["PublicName"] = options.Value.PublicName;
        if (id is null || id.Length < 5) return Redirect("./error"); // generic error, no throttle

        var found = await db.Links.AsNoTracking().Servable(time.GetUtcNow())
            .Where(l => l.Id == id)
            .Join(db.StoredContents, l => l.ContentId, c => c.Id, (l, c) => new { Link = l, c.SizeBytes })
            .FirstOrDefaultAsync(ct);
        if (found is null)
            return await throttle.WaitAsync(ThrottleKind.UnknownLink, HttpContext)
                ? Redirect("./error")
                : StatusCode(StatusCodes.Status429TooManyRequests);

        Link = found.Link;
        Size = LinkRules.FormatSize(found.SizeBytes);
        return null;
    }
}
