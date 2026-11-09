using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Qhub.Tests.Support;

namespace Qhub.Tests;

[TestClass]
public sealed class StartupSmokeTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task AppStartsAgainstSqlServerAndHealthReturns200()
    {
        await using var factory = new QhubFactory(QhubFactory.ValidSettings(await SqlServer.NewDatabaseAsync()));
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health", TestContext.CancellationToken);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>The start page and the API documentation open from their folder addresses, as in the legacy file server.</summary>
    [TestMethod]
    public async Task StartPageAndApiDocumentationOpen()
    {
        await using var factory = new QhubFactory(QhubFactory.ValidSettings(await SqlServer.NewDatabaseAsync()));
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });

        using var root = await client.GetAsync("/", TestContext.CancellationToken);
        using var noSlash = await client.GetAsync("/apidocumentation", TestContext.CancellationToken);
        using var docs = await client.GetAsync("/apidocumentation/", TestContext.CancellationToken);

        Assert.Contains("URL=./index", await root.Content.ReadAsStringAsync(TestContext.CancellationToken));
        Assert.EndsWith("/apidocumentation/", noSlash.Headers.Location?.OriginalString ?? "");
        Assert.Contains("swagger", await docs.Content.ReadAsStringAsync(TestContext.CancellationToken));
    }

    /// <summary>Every openapi.json operation is routed with its documented method only (spec §3.1 F1) and answers in the legacy error shape.</summary>
    [TestMethod]
    public async Task EveryOpenApiOperationIsMappedWithItsMethod()
    {
        await using var factory = new QhubFactory(QhubFactory.ValidSettings(await SqlServer.NewDatabaseAsync()));
        using var client = factory.CreateClient();
        var contract = factory.Services.GetRequiredService<IWebHostEnvironment>().WebRootFileProvider.GetFileInfo("apidocumentation/openapi.json");
        using var stream = contract.CreateReadStream();
        using var spec = await JsonDocument.ParseAsync(stream, cancellationToken: TestContext.CancellationToken);

        var operations = 0;
        foreach (var path in spec.RootElement.GetProperty("paths").EnumerateObject())
        {
            foreach (var operation in path.Value.EnumerateObject())
            {
                var url = "/api" + path.Name.Replace("{id}", "abc", StringComparison.Ordinal);
                using var request = new HttpRequestMessage(new HttpMethod(operation.Name.ToUpperInvariant()), url);
                using var response = await client.SendAsync(request, TestContext.CancellationToken);
                Assert.AreNotEqual(HttpStatusCode.NotFound, response.StatusCode, $"{operation.Name} {url}");
                Assert.AreNotEqual(HttpStatusCode.MethodNotAllowed, response.StatusCode, $"{operation.Name} {url}");
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.CancellationToken));
                if (url == "/api/info/version")
                {
                    Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, "the version needs no key (spec F4)");
                }
                else
                {
                    // Without a key: 401 InvalidApiKey, or 501 for an operation not built yet; always the legacy error shape.
                    Assert.AreEqual("error", body.RootElement.GetProperty("Result").GetString(), $"{operation.Name} {url}");
                    Assert.Contains(body.RootElement.GetProperty("ErrorCode").GetInt32(), new[] { 0, 2 });
                }
                operations++;
            }
        }

        Assert.AreEqual(31, operations);
        using var wrongMethod = await client.GetAsync("/api/files/add", TestContext.CancellationToken);
        Assert.AreEqual(HttpStatusCode.MethodNotAllowed, wrongMethod.StatusCode);
    }
}
