using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Qhub.Data;
using Qhub.Domain;

namespace Qhub.Tests.Support;

/// <summary>Issuing systems calling <c>/api</c> with a Bearer key.</summary>
public static class Api
{
    static int nextUser, nextIp = 100;

    public const ApiPermissions AllKeyPermissions = ApiPermissions.View | ApiPermissions.Upload | ApiPermissions.Delete | ApiPermissions.ApiManage
        | ApiPermissions.Edit | ApiPermissions.Replace | ApiPermissions.ManageUsers | ApiPermissions.ManageLogs | ApiPermissions.Download;

    public sealed record Caller(HttpClient Client, int UserId, string Key) : IDisposable
    {
        public void Dispose() => Client.Dispose();
    }

    /// <summary>A new user with one API key, seeded in the database, and a client sending that key.</summary>
    public static async Task<Caller> NewCallerAsync(this QhubFactory app, UserPermissions permissions = UserPermissions.None,
        ApiPermissions keyPermissions = AllKeyPermissions, UserRank rank = UserRank.User, DateTimeOffset? keyExpires = null)
    {
        var secret = RandomNumberGenerator.GetString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 30);
        int userId;
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<QhubDbContext>();
            var user = new User { Name = $"api-user-{Interlocked.Increment(ref nextUser)}-{Guid.NewGuid():N}"[..40], Rank = rank, Permissions = permissions, SecurityStamp = "s" };
            db.Users.Add(user);
            await db.SaveChangesAsync();
            db.ApiKeys.Add(new ApiKey
            {
                Id = Guid.NewGuid().ToString("N"),
                OwnerId = user.Id,
                SecretHash = SHA256.HashData(Encoding.UTF8.GetBytes(secret)),
                Permissions = keyPermissions,
                ExpiresAt = keyExpires,
            });
            await db.SaveChangesAsync();
            userId = user.Id;
        }
        return new Caller(app.KeyClient(secret), userId, secret);
    }

    public static HttpClient KeyClient(this QhubFactory app, string? secret)
    {
        var client = app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        client.DefaultRequestHeaders.Add("X-Forwarded-For", $"198.51.100.{Interlocked.Increment(ref nextIp) % 250 + 1}");
        if (secret is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        return client;
    }

    /// <summary>A <c>/files/add</c>-style multipart body.</summary>
    public static MultipartFormDataContent Upload(byte[] bytes, string fileName = "statement.pdf", params (string Name, string Value)[] fields)
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        form.Add(file, "file", fileName);
        foreach (var (name, value) in fields) form.Add(new StringContent(value), name);
        return form;
    }

    public static byte[] Pdf(int size = 3000, string tag = "")
    {
        var bytes = new byte[size];
        RandomNumberGenerator.Fill(bytes);
        Encoding.ASCII.GetBytes("%PDF-" + tag).CopyTo(bytes, 0);
        return bytes;
    }

    /// <summary>Uploads with code 4821 and returns <c>FileInfo</c>.</summary>
    public static async Task<JsonElement> AddAsync(this Caller caller, byte[] bytes, params (string Name, string Value)[] fields)
    {
        var all = fields.Any(f => f.Name == "password") ? fields : [.. fields, ("password", "4821")];
        using var response = await caller.Client.PostAsync("/api/files/add", Upload(bytes, fields: all));
        var json = await response.JsonAsync();
        Assert.AreEqual(System.Net.HttpStatusCode.OK, response.StatusCode, json.ToString());
        return json.GetProperty("FileInfo");
    }

    public static async Task<HttpResponseMessage> SendAsync(this Caller caller, HttpMethod method, string url, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(method, url);
        foreach (var (name, value) in headers) request.Headers.TryAddWithoutValidation(name, value);
        return await caller.Client.SendAsync(request);
    }

    public static async Task<JsonElement> JsonAsync(this HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        return text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    public static void AssertError(HttpResponseMessage response, System.Net.HttpStatusCode status, int errorCode, JsonElement json, string? messagePart = null)
    {
        Assert.AreEqual(status, response.StatusCode, json.ToString());
        Assert.AreEqual("error", json.GetProperty("Result").GetString());
        Assert.AreEqual(errorCode, json.GetProperty("ErrorCode").GetInt32(), json.ToString());
        if (messagePart is not null) Assert.Contains(messagePart, json.GetProperty("ErrorMessage").GetString()!);
    }
}
