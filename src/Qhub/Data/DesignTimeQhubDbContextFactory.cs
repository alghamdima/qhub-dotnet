using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Qhub.Data;

/// <summary>Lets <c>dotnet ef</c> build the model without QHUB_* settings. It never connects.</summary>
public sealed class DesignTimeQhubDbContextFactory : IDesignTimeDbContextFactory<QhubDbContext>
{
    public QhubDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<QhubDbContext>().UseSqlServer("Server=design-time-only").Options);
}
