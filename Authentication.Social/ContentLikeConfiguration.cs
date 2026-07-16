using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Authentication.Social;

/// <summary>
/// Maps <see cref="ContentLike"/>, and defines the unique index the like logic depends on.
/// </summary>
/// <remarks>
/// The constraint here is not belt-and-braces around an application check. It is the only
/// thing that actually holds: two requests can both find no existing like and both go on to
/// insert one, and no amount of checking first closes that window. The database is the only
/// place the rule can be enforced, so the code that inserts a like is written to expect this
/// index to reject it.
/// </remarks>
internal sealed class ContentLikeConfiguration : IEntityTypeConfiguration<ContentLike>
{
    /// <summary>
    /// The unique index over (UserId, ContentType, ContentId), named so a duplicate-key
    /// failure is identifiable rather than guessed at.
    /// </summary>
    internal const string UniqueIndexName = "IX_ContentLikes_UserId_ContentType_ContentId";

    public void Configure(EntityTypeBuilder<ContentLike> builder)
    {
        builder.ToTable("ContentLikes");

        builder.HasKey(l => l.Id);

        // Bounded so they can be indexed. Providers refuse to index an unbounded text column,
        // and without the index the uniqueness rule below has nothing to stand on.
        builder.Property(l => l.UserId).HasMaxLength(450).IsRequired();
        builder.Property(l => l.ContentType).HasMaxLength(128).IsRequired();
        builder.Property(l => l.CreatedAt).IsRequired();

        // A like IS this triple. The index makes that true rather than merely intended, and
        // is what a concurrent double-insert collides with.
        builder
            .HasIndex(l => new { l.UserId, l.ContentType, l.ContentId })
            .IsUnique()
            .HasDatabaseName(UniqueIndexName);

        // Counting likes for an item, and listing recent ones for an activity feed. Both
        // read by content, so both start with the content key; CreatedAt descending serves
        // "most recent first" from the index rather than from a sort.
        builder
            .HasIndex(l => new { l.ContentType, l.ContentId, l.CreatedAt })
            .HasDatabaseName("IX_ContentLikes_ContentType_ContentId_CreatedAt");

        // "What has this user liked lately", which the unique index cannot serve: its leading
        // column is UserId, but it has no CreatedAt to order by.
        builder
            .HasIndex(l => new { l.UserId, l.CreatedAt })
            .HasDatabaseName("IX_ContentLikes_UserId_CreatedAt");
    }
}
