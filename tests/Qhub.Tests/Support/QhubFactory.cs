using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;

namespace Qhub.Tests.Support;

/// <summary>The real app with the given <c>QHUB_*</c> settings layered over the environment.</summary>
/// <remarks>
/// Time is a <see cref="FakeTimeProvider"/> starting at <see cref="Start"/>. Every request arrives from <see cref="ProxyIp"/>, a trusted
/// proxy, so a test picks its client IP with <c>X-Forwarded-For</c>, as behind the production reverse proxy.
/// </remarks>
/// The hourly clean-up worker is off unless <paramref name="cleanupWorker"/>: advancing the shared fake clock would otherwise run it
/// in the middle of other tests; tests call <c>Cleanup.RunAsync</c> directly.
public sealed class QhubFactory(IDictionary<string, string?> settings, bool cleanupWorker = false) : WebApplicationFactory<Program>
{
    public static readonly DateTimeOffset Start = new(2026, 11, 22, 10, 0, 0, TimeSpan.Zero);
    public const string ProxyIp = "10.99.0.1";

    public FakeTimeProvider Time { get; } = new(Start);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration(c => c.AddInMemoryCollection(settings));
        builder.ConfigureServices(s =>
        {
            s.AddSingleton<TimeProvider>(Time);
            s.AddSingleton<IStartupFilter, FromProxy>();
            if (!cleanupWorker)
            {
                var worker = s.Single(d => d.ServiceType == typeof(IHostedService) && d.ImplementationType == typeof(Qhub.Features.Retention.CleanupWorker));
                s.Remove(worker);
            }
        });
    }

    /// <summary>TestServer has no peer address; give every request the proxy's.</summary>
    sealed class FromProxy : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(ProxyIp);
                return nextMiddleware(context);
            });
            next(app);
        };
    }

    /// <summary>Fake, same-shape settings that pass validation. No legacy or real credential.</summary>
    public static Dictionary<string, string?> ValidSettings(string dbConnection)
    {
        // Program reads this one before Build(), as in production, where factory overrides may not be visible yet.
        Environment.SetEnvironmentVariable("QHUB_DATA_PROTECTION_CERT_FILE", DataProtectionCertFile.Value);
        return new()
        {
            ["QHUB_PUBLIC_URL"] = "https://qhub.test/",
            ["QHUB_AUTH"] = "internal",
            ["QHUB_ADMIN_USER"] = "admin",
            ["QHUB_ADMIN_PASSWORD"] = "fake-admin-password-0000",
            ["QHUB_SERVER_KEY"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ["QHUB_DB_CONNECTION"] = dbConnection,
            ["QHUB_DATA_PROTECTION_CERT_FILE"] = DataProtectionCertFile.Value,
            ["QHUB_TRUSTED_PROXIES"] = ProxyIp,
            ["QHUB_DATA_DIR"] = Directory.CreateTempSubdirectory("qhub-tests-data-").FullName,
            ["QHUB_CHUNK_SIZE_MB"] = "1", // chunks of 1 MB keep the chunk tests small
        };
    }

    /// <summary>A throwaway self-signed PEM (certificate + key), created once per run.</summary>
    static readonly Lazy<string> DataProtectionCertFile = new(() =>
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=qhub-tests", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var path = Path.Combine(Path.GetTempPath(), $"qhub-tests-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, cert.ExportCertificatePem() + "\n" + rsa.ExportPkcs8PrivateKeyPem());
        return path;
    });
}
