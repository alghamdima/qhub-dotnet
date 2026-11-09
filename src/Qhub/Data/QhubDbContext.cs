using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Qhub.Domain;

namespace Qhub.Data;

public sealed class QhubDbContext(DbContextOptions<QhubDbContext> options) : DbContext(options), IDataProtectionKeyContext
{
    public DbSet<Link> Links => Set<Link>();
    public DbSet<StoredContent> StoredContents => Set<StoredContent>();
    public DbSet<User> Users => Set<User>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<CodeLock> CodeLocks => Set<CodeLock>();
    public DbSet<CountedPass> CountedPasses => Set<CountedPass>();
    public DbSet<DownloadGrant> DownloadGrants => Set<DownloadGrant>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<TrafficStat> TrafficStats => Set<TrafficStat>();
    public DbSet<KeyCheck> KeyChecks => Set<KeyCheck>();
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    /// <summary>Link, key, pass and grant IDs are case-sensitive (architecture §3).</summary>
    static void CaseSensitiveId(PropertyBuilder p) => p.HasMaxLength(64).IsUnicode(false).UseCollation("Latin1_General_100_BIN2");

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<User>(e =>
        {
            e.Property(u => u.Name).HasMaxLength(128);
            e.HasIndex(u => u.Name).IsUnique();
            e.Property(u => u.PasswordHash).HasMaxLength(256);
            e.Property(u => u.SecurityStamp).HasMaxLength(64);
        });

        model.Entity<StoredContent>(e =>
        {
            e.Property(c => c.DedupKey).HasMaxLength(32);
            e.HasIndex(c => c.DedupKey).IsUnique();
            e.Property(c => c.Location).HasMaxLength(1024);
            e.Property(c => c.WrappedKey).HasMaxLength(256);
        });

        model.Entity<Link>(e =>
        {
            CaseSensitiveId(e.Property(l => l.Id));
            e.Property(l => l.FileName).HasMaxLength(512);
            e.Property(l => l.ContentType).HasMaxLength(255).IsUnicode(false);
            e.Property(l => l.AccessCodeMac).HasMaxLength(32);
            e.HasOne<User>().WithMany().HasForeignKey(l => l.OwnerId).OnDelete(DeleteBehavior.Restrict);
            // Restrict: content is deleted only when no link uses it (RULE-111).
            e.HasOne<StoredContent>().WithMany().HasForeignKey(l => l.ContentId).OnDelete(DeleteBehavior.Restrict);
            // Every non-reserved link has content and a customer code (RULE-068, RULE-052 corrected).
            e.ToTable(t => t.HasCheckConstraint("CK_Links_ContentAndCodeUnlessReserved",
                "[State] = 0 OR ([ContentId] IS NOT NULL AND [AccessCodeMac] IS NOT NULL)"));
        });

        model.Entity<CodeLock>(e =>
        {
            e.HasKey(c => c.LinkId);
            CaseSensitiveId(e.Property(c => c.LinkId));
            e.HasOne<Link>().WithOne().HasForeignKey<CodeLock>(c => c.LinkId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<ApiKey>(e =>
        {
            CaseSensitiveId(e.Property(k => k.Id));
            e.Property(k => k.SecretHash).HasMaxLength(32);
            e.HasIndex(k => k.SecretHash).IsUnique();
            e.Property(k => k.FriendlyName).HasMaxLength(256);
            e.HasOne<User>().WithMany().HasForeignKey(k => k.OwnerId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<CountedPass>(e =>
        {
            e.HasKey(p => p.PassId);
            CaseSensitiveId(e.Property(p => p.PassId));
            CaseSensitiveId(e.Property(p => p.LinkId));
            e.HasOne<Link>().WithMany().HasForeignKey(p => p.LinkId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<DownloadGrant>(e =>
        {
            CaseSensitiveId(e.Property(g => g.Id));
            e.Property(g => g.LinkIds).IsUnicode(false).UseCollation("Latin1_General_100_BIN2");
            e.HasOne<User>().WithMany().HasForeignKey(g => g.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<AuditEntry>(e =>
        {
            e.Property(a => a.Action).HasMaxLength(64);
            CaseSensitiveId(e.Property(a => a.LinkId));
            e.Property(a => a.Detail).HasMaxLength(2000);
            e.Property(a => a.ClientIp).HasMaxLength(45).IsUnicode(false);
            e.HasOne<User>().WithMany().HasForeignKey(a => a.ActorUserId).OnDelete(DeleteBehavior.SetNull);
        });

        model.Entity<TrafficStat>().HasKey(t => t.Day);

        model.Entity<KeyCheck>(e =>
        {
            e.Property(k => k.Id).ValueGeneratedNever();
            e.Property(k => k.Salt).HasMaxLength(32);
            e.Property(k => k.Verifier).HasMaxLength(64);
            e.Property(k => k.Mode).HasMaxLength(8).IsUnicode(false);
            e.ToTable(t => t.HasCheckConstraint("CK_KeyChecks_SingleRow", "[Id] = 1"));
        });
    }
}
