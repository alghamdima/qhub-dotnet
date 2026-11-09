using Microsoft.EntityFrameworkCore;

namespace Qhub.Data;

public static class DatabaseStartup
{
    /// <summary>
    /// RULE-037: refuses a database that holds migrations this build does not know, then applies this build's.
    /// The app's database login therefore needs DDL rights.
    /// </summary>
    public static async Task MigrateAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<QhubDbContext>();
        var unknown = (await db.Database.GetAppliedMigrationsAsync(cancellationToken)).Except(db.Database.GetMigrations()).ToList();
        if (unknown.Count > 0)
        {
            throw new InvalidOperationException(
                $"Unable to continue: the database holds migrations this build does not know ({string.Join(", ", unknown)}). Run the newer Qhub build.");
        }
        await db.Database.MigrateAsync(cancellationToken);
    }
}
