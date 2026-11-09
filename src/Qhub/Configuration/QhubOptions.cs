using System.Globalization;

namespace Qhub.Configuration;

/// <summary>
/// The operator settings: <c>QHUB_*</c> environment variables (spec §3.6). Secrets also accept <c>QHUB_X_FILE</c>
/// (Docker secrets); setting both forms is an error. No secret has a default.
/// </summary>
public sealed class QhubOptions
{
    public int Port { get; set; } = 53842;
    public string PublicUrl { get; set; } = "";
    public string PublicName { get; set; } = "Qhub";
    public string RedirectUrl { get; set; } = "";
    public string TrustedProxies { get; set; } = "127.0.0.1";
    public string Auth { get; set; } = "internal";
    public string AdminUser { get; set; } = "admin";
    public string AdminPassword { get; set; } = "";
    public string SamlIdpMetadata { get; set; } = "";
    public int MinLengthPassword { get; set; } = 8;
    public bool DisableApiMenu { get; set; }
    public int ChunkSizeMb { get; set; } = 45;
    public int MaxFileSizeMb { get; set; } = 50;
    public int MaxMemoryUploadMb { get; set; } = 50;
    public int MaxParallelUploads { get; set; } = 3;
    public int MinFreeSpaceMb { get; set; } = 400;
    public int LengthId { get; set; } = 15;
    public bool LogStdout { get; set; }
    public int LogRetentionDays { get; set; }
    public bool SaveIp { get; set; }
    public string Encryption { get; set; } = "none";
    public string EncryptionPassword { get; set; } = "";
    public string DataDir { get; set; } = "data";
    public string AwsBucket { get; set; } = "";
    public string AwsRegion { get; set; } = "";
    public string AwsKey { get; set; } = "";
    public string AwsKeySecret { get; set; } = "";
    public string AwsEndpoint { get; set; } = "";
    public bool AwsProxyDownload { get; set; }
    public string DbConnection { get; set; } = "";
    /// <summary>Base64 of 32 random bytes: the HMAC key for access codes and the dedup key.</summary>
    public string ServerKey { get; set; } = "";
    /// <summary>PEM file holding the certificate and private key that encrypt the Data Protection keys.</summary>
    public string DataProtectionCertFile { get; set; } = "";

    /// <summary>Problems found while reading the variables; <see cref="QhubOptionsValidator"/> reports them with the rest.</summary>
    public List<string> LoadErrors { get; } = [];

    public void Load(IConfiguration c)
    {
        string Text(string name, string fallback) => c["QHUB_" + name] is { Length: > 0 } v ? v : fallback;

        int Number(string name, int fallback)
        {
            var v = c["QHUB_" + name];
            if (string.IsNullOrEmpty(v)) return fallback;
            if (int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return n;
            LoadErrors.Add($"QHUB_{name} must be a whole number, got \"{v}\"");
            return fallback;
        }

        bool Flag(string name, bool fallback)
        {
            var v = c["QHUB_" + name];
            if (string.IsNullOrEmpty(v)) return fallback;
            if (bool.TryParse(v, out var b)) return b;
            if (v is "1" or "0") return v == "1";
            LoadErrors.Add($"QHUB_{name} must be true or false, got \"{v}\"");
            return fallback;
        }

        // Never echoes the value: these are secrets.
        string Secret(string name)
        {
            var direct = c["QHUB_" + name];
            var file = c["QHUB_" + name + "_FILE"];
            if (string.IsNullOrEmpty(file)) return direct ?? "";
            if (!string.IsNullOrEmpty(direct))
            {
                LoadErrors.Add($"Set QHUB_{name} or QHUB_{name}_FILE, not both");
                return "";
            }
            try
            {
                return File.ReadAllText(file).TrimEnd('\r', '\n');
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                LoadErrors.Add($"QHUB_{name}_FILE could not be read: {e.Message}");
                return "";
            }
        }

        Port = Number("PORT", Port);
        PublicUrl = Text("PUBLIC_URL", PublicUrl);
        PublicName = Text("PUBLIC_NAME", PublicName);
        RedirectUrl = Text("REDIRECT_URL", RedirectUrl);
        TrustedProxies = Text("TRUSTED_PROXIES", TrustedProxies);
        Auth = Text("AUTH", Auth);
        AdminUser = Text("ADMIN_USER", AdminUser);
        AdminPassword = Secret("ADMIN_PASSWORD");
        SamlIdpMetadata = Text("SAML_IDP_METADATA", SamlIdpMetadata);
        MinLengthPassword = Number("MIN_LENGTH_PASSWORD", MinLengthPassword);
        DisableApiMenu = Flag("DISABLE_API_MENU", DisableApiMenu);
        ChunkSizeMb = Number("CHUNK_SIZE_MB", ChunkSizeMb);
        MaxFileSizeMb = Number("MAX_FILESIZE", MaxFileSizeMb);
        MaxMemoryUploadMb = Number("MAX_MEMORY_UPLOAD", MaxMemoryUploadMb);
        MaxParallelUploads = Number("MAX_PARALLEL_UPLOADS", MaxParallelUploads);
        MinFreeSpaceMb = Number("MIN_FREE_SPACE", MinFreeSpaceMb);
        LengthId = Number("LENGTH_ID", LengthId);
        LogStdout = Flag("LOG_STDOUT", LogStdout);
        LogRetentionDays = Number("LOG_RETENTION_DAYS", LogRetentionDays);
        SaveIp = Flag("SAVE_IP", SaveIp);
        Encryption = Text("ENCRYPTION", Encryption).ToLowerInvariant();
        EncryptionPassword = Secret("ENCRYPTION_PASSWORD");
        DataDir = Text("DATA_DIR", DataDir);
        AwsBucket = Text("AWS_BUCKET", AwsBucket);
        AwsRegion = Text("AWS_REGION", AwsRegion);
        AwsKey = Text("AWS_KEY", AwsKey);
        AwsKeySecret = Secret("AWS_KEY_SECRET");
        AwsEndpoint = Text("AWS_ENDPOINT", AwsEndpoint);
        AwsProxyDownload = Flag("AWS_PROXY_DOWNLOAD", AwsProxyDownload);
        DbConnection = Secret("DB_CONNECTION");
        ServerKey = Secret("SERVER_KEY");
        DataProtectionCertFile = Text("DATA_PROTECTION_CERT_FILE", DataProtectionCertFile);
    }
}
