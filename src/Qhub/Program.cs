using System.Net;
using System.Threading.Channels;
using System.Text.Encodings.Web;
using System.Text.Unicode;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qhub.Configuration;
using Qhub.Data;
using Qhub.Features.Admin;
using Qhub.Features.Audit;
using Qhub.Features.Branding;
using Qhub.Features.Api;
using Qhub.Features.Delivery;
using Qhub.Features.Identity;
using Qhub.Features.Documents;
using Qhub.Features.Portal;
using Qhub.Features.Retention;
using Qhub.Features.Storage;
using Qhub.Features.Uploads;
using Qhub.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOptions<QhubOptions>().Configure<IConfiguration>((o, c) => o.Load(c)).ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<QhubOptions>, QhubOptionsValidator>();
builder.Services.AddOptions<KestrelServerOptions>().Configure<IOptions<QhubOptions>>((k, q) => k.ListenAnyIP(q.Value.Port));
builder.Services.AddDbContext<QhubDbContext>((sp, db) => db.UseSqlServer(sp.GetRequiredService<IOptions<QhubOptions>>().Value.DbConnection));

// Keys live in SQL Server, encrypted with the operator's certificate, so a database dump can't forge passes or sessions.
// The certificate is needed at registration; a missing or bad file is reported by the validator, which stops the app.
var dataProtection = builder.Services.AddDataProtection().SetApplicationName("qhub").PersistKeysToDbContext<QhubDbContext>();
if (QhubOptionsValidator.TryLoadCertificate(builder.Configuration["QHUB_DATA_PROTECTION_CERT_FILE"]) is { } certificate)
    dataProtection.ProtectKeysWithCertificate(certificate).UnprotectKeysWithAnyCertificate(certificate);

builder.Services.AddHealthChecks();
builder.Services.AddRazorPages();
// Arabic pages: write the text as-is, not as &#x...; entities (HTML-special characters are still encoded).
builder.Services.Configure<Microsoft.Extensions.WebEncoders.WebEncoderOptions>(o => o.TextEncoderSettings = new TextEncoderSettings(UnicodeRanges.All));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<AccessCodes>();
builder.Services.AddSingleton<ClientThrottle>();
builder.Services.AddSingleton<CustomerTexts>();
builder.Services.AddSingleton<Passes>();
builder.Services.AddSingleton<ContentEncryption>();
builder.Services.AddSingleton<ContentStore>();
builder.Services.AddSingleton<UploadStatusHub>();
builder.Services.AddSingleton(Channel.CreateUnbounded<CompleteUpload>());
builder.Services.AddSingleton<Passwords>();
builder.Services.AddSingleton<Branding>();
builder.Services.AddSingleton<ServerStats>();
builder.Services.AddSessions();
builder.Services.AddScoped<CodeAttempts>();
builder.Services.AddScoped<Documents>();
builder.Services.AddScoped<Chunks>();
builder.Services.AddScoped<Cleanup>();
builder.Services.AddHostedService<UploadCompletionWorker>();
builder.Services.AddHostedService<CleanupWorker>();

// The client IP (for the per-IP throttles) comes from X-Forwarded-For only when the peer is a trusted proxy (SEC-008).
builder.Services.AddOptions<ForwardedHeadersOptions>().Configure<IOptions<QhubOptions>>((f, q) =>
{
    f.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    f.ForwardLimit = 1;
    f.KnownProxies.Clear();
    f.KnownIPNetworks.Clear();
    foreach (var proxy in q.Value.TrustedProxies.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        f.KnownIPNetworks.Add(System.Net.IPNetwork.TryParse(proxy, out var network) ? network : new System.Net.IPNetwork(IPAddress.Parse(proxy), IPAddress.Parse(proxy).GetAddressBytes().Length * 8));
});

var app = builder.Build();

// Report every setting error (RULE-038) before anything touches the database.
_ = app.Services.GetRequiredService<IOptions<QhubOptions>>().Value;
await DatabaseStartup.MigrateAsync(app.Services);
using (var scope = app.Services.CreateScope())
{
    // Stops startup on a wrong encryption password or a mode change that would strand encrypted files (RULE-002, RULE-039).
    await app.Services.GetRequiredService<ContentEncryption>().InitializeAsync(
        scope.ServiceProvider.GetRequiredService<QhubDbContext>(), app.Services.GetRequiredService<IOptions<QhubOptions>>().Value, CancellationToken.None);
}
await SuperAdmin.UpsertAsync(app.Services, CancellationToken.None);

app.UseForwardedHeaders();
app.Use((http, next) =>
{
    // Legacy security headers (Webserver.go securityHeaders).
    var h = http.Response.Headers;
    h.XContentTypeOptions = "nosniff";
    h.XFrameOptions = "DENY";
    h["Referrer-Policy"] = "same-origin";
    if (http.Request.IsHttps) h.StrictTransportSecurity = "max-age=31536000";
    return next(http);
});
// Like the legacy file server: "/" and "/apidocumentation/" serve their index.html ("/apidocumentation" redirects to the slash form).
app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions { OnPrepareResponse = c => c.Context.Response.Headers.CacheControl = "public, max-age=36000" });
app.UseAuthentication();
app.UseMiddleware<CrossOriginGuard>();
app.MapHealthChecks("/health");
app.MapApi();
app.MapRazorPages();
app.MapDelivery();
app.MapAdmin();
app.MapBranding();

app.Run();
