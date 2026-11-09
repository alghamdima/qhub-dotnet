using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

[assembly: DoNotParallelize]

namespace Qhub.Tests.Support;

/// <summary>
/// One SQL Server per test run; each test gets its own new database in it. A container is started on first use, unless
/// <c>QHUB_TEST_SQL</c> holds a connection string to a server that is already running (much faster locally).
/// </summary>
[TestClass]
public sealed class SqlServer
{
    const string Image = "mcr.microsoft.com/mssql/server:2022-latest";
    // Bounded so a missing Docker or a stuck pull fails the run instead of hanging it.
    static readonly TimeSpan StartTimeout = TimeSpan.FromMinutes(10);

    static MsSqlContainer? container;
    static Task<string>? server;

    // Started on first use, so a run without database tests never waits on Docker.
    static async Task<string> ServerAsync()
    {
        server ??= StartAsync();
        try { return await server; }
        catch (Exception e)
        {
            Assert.Fail($"SQL Server container ({Image}) is not available. Is Docker running?{Environment.NewLine}{e}");
            throw;
        }
    }

    static async Task<string> StartAsync()
    {
        if (Environment.GetEnvironmentVariable("QHUB_TEST_SQL") is { Length: > 0 } existing) return existing;
        using var timeout = new CancellationTokenSource(StartTimeout);
        container = new MsSqlBuilder(Image).Build();
        await container.StartAsync(timeout.Token);
        return container.GetConnectionString();
    }

    [AssemblyCleanup]
    public static async Task StopAsync()
    {
        if (container is not null) await container.DisposeAsync();
    }

    /// <summary>A connection string to a database that does not exist yet; the app's migration creates it.</summary>
    public static async Task<string> NewDatabaseAsync() =>
        new SqlConnectionStringBuilder(await ServerAsync())
        {
            InitialCatalog = "qhub_" + Guid.NewGuid().ToString("N"),
            CommandTimeout = 120, // a freshly started container is slow to create the first database
        }.ConnectionString;
}
