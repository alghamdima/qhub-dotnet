using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace Qhub.Configuration;

/// <summary>RULE-038: checks every setting and reports all errors at once; the app stops with the list.</summary>
public sealed class QhubOptionsValidator : IValidateOptions<QhubOptions>
{
    public ValidateOptionsResult Validate(string? name, QhubOptions o)
    {
        var errors = new List<string>(o.LoadErrors);
        void Check(bool ok, string error)
        {
            if (!ok) errors.Add(error);
        }

        var auth = o.Auth.ToLowerInvariant().Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        Check(auth.Length > 0 && auth.All(a => a is "internal" or "saml"), "QHUB_AUTH must be internal, saml or both, separated by a comma");
        var authInternal = auth.Contains("internal");
        var authSaml = auth.Contains("saml");

        // SEC-013: http:// only for local development.
        Check(Uri.TryCreate(o.PublicUrl, UriKind.Absolute, out var url)
              && (url.Scheme == Uri.UriSchemeHttps || (url.Scheme == Uri.UriSchemeHttp && url.IsLoopback)),
            "QHUB_PUBLIC_URL must be the https:// address users open Qhub at, e.g. https://files.example.com/ (http:// only for localhost)");
        Check(o.AdminUser.Length >= 3, "QHUB_ADMIN_USER must be at least 3 characters long");
        Check(o.MinLengthPassword >= 6, "QHUB_MIN_LENGTH_PASSWORD must be at least 6");
        if (authInternal)
            Check(o.AdminPassword.Length >= o.MinLengthPassword, $"QHUB_ADMIN_PASSWORD must be at least {o.MinLengthPassword} characters long");
        if (authSaml)
        {
            // shortcut: SAML (RULE-066) is deferred at the user's request, refuse it instead of showing a dead button; remove when /saml-acs exists.
            Check(false, "QHUB_AUTH=saml is not available in this version yet; use internal");
            Check(o.SamlIdpMetadata.Length > 0, "QHUB_SAML_IDP_METADATA is empty");
            // The metadata carries the IdP certificate: tampering with it in transit allows logging in as anyone.
            Check(!o.SamlIdpMetadata.StartsWith("http://", StringComparison.OrdinalIgnoreCase), "QHUB_SAML_IDP_METADATA must be an https:// URL or a file");
        }

        Check(o.Encryption is "none" or "on", "QHUB_ENCRYPTION must be none or on");
        if (o.Encryption == "on")
        {
            Check(o.EncryptionPassword.Length >= o.MinLengthPassword, $"QHUB_ENCRYPTION_PASSWORD must be at least {o.MinLengthPassword} characters long");
            // Brief Q4: S3 relies on the bucket's server-side encryption.
            Check(o.AwsBucket.Length == 0, "QHUB_ENCRYPTION=on encrypts local storage only; with QHUB_AWS_BUCKET use the bucket's server-side encryption and set QHUB_ENCRYPTION=none");
        }
        if (o.AwsBucket.Length > 0)
        {
            Check(o.AwsRegion.Length > 0, "QHUB_AWS_REGION is required with QHUB_AWS_BUCKET");
            Check(o.AwsKey.Length > 0 && o.AwsKeySecret.Length > 0, "QHUB_AWS_KEY and QHUB_AWS_KEY_SECRET (or QHUB_AWS_KEY_SECRET_FILE) are required with QHUB_AWS_BUCKET");
            Check(o.AwsEndpoint.Length == 0 || Uri.TryCreate(o.AwsEndpoint, UriKind.Absolute, out _), "QHUB_AWS_ENDPOINT must be an absolute URL");
        }

        Check(o.DbConnection.Length > 0, "QHUB_DB_CONNECTION (or QHUB_DB_CONNECTION_FILE) is required");
        Check(IsServerKey(o.ServerKey), "QHUB_SERVER_KEY (or QHUB_SERVER_KEY_FILE) must be 32 random bytes, base64-encoded");
        if (CertificateError(o.DataProtectionCertFile) is { } certError)
            errors.Add("QHUB_DATA_PROTECTION_CERT_FILE " + certError);

        Check(o.Port is > 0 and <= 65535, "QHUB_PORT must be between 1 and 65535");
        Check(o.ChunkSizeMb > 0, "QHUB_CHUNK_SIZE_MB must be positive");
        Check(o.MaxFileSizeMb > 0, "QHUB_MAX_FILESIZE must be positive");
        Check(o.MaxMemoryUploadMb > 0, "QHUB_MAX_MEMORY_UPLOAD must be positive");
        Check(o.MaxParallelUploads > 0, "QHUB_MAX_PARALLEL_UPLOADS must be positive");
        Check(o.MinFreeSpaceMb >= 0, "QHUB_MIN_FREE_SPACE must not be negative");
        Check(o.LogRetentionDays >= 0, "QHUB_LOG_RETENTION_DAYS must not be negative");
        // Values under 5 are raised to 5 (RULE-004); 64 is the ID column width.
        Check(o.LengthId <= 64, "QHUB_LENGTH_ID must be at most 64");
        foreach (var proxy in o.TrustedProxies.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            Check(IPNetwork.TryParse(proxy, out _) || IPAddress.TryParse(proxy, out _), $"QHUB_TRUSTED_PROXIES: \"{proxy}\" is not an IP address or CIDR range");

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    static bool IsServerKey(string value)
    {
        Span<byte> key = stackalloc byte[33];
        return Convert.TryFromBase64String(value, key, out var length) && length == 32;
    }

    static string? CertificateError(string path)
    {
        if (path.Length == 0) return "is required";
        try
        {
            using var cert = X509Certificate2.CreateFromPemFile(path);
            return cert.HasPrivateKey ? null : "must hold the private key as well as the certificate";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
        {
            return $"could not be loaded as a PEM certificate with its private key: {e.Message}";
        }
    }

    /// <summary>One PEM file with the certificate and its private key, or null when it is unusable (the validator says why).</summary>
    public static X509Certificate2? TryLoadCertificate(string? path) =>
        string.IsNullOrEmpty(path) || CertificateError(path) is not null ? null : X509Certificate2.CreateFromPemFile(path);
}
