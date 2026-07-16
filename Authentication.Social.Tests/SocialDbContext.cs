using Authentication.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Social.Tests;

/// <summary>
/// A host context, wired the way the README tells hosts to wire one.
/// </summary>
/// <remarks>
/// Shared by every test in this package, and deliberately the whole arrangement rather than
/// only the social tables: a host that has the social tables and not the auth ones is not a
/// host any of this is written for, and testing against one would hide the fact that they
/// share a context on purpose.
/// </remarks>
internal sealed class SocialDbContext : ReusableAuthDbContext
{
    public SocialDbContext(DbContextOptions<SocialDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddReusableAuthSocial();
    }
}
