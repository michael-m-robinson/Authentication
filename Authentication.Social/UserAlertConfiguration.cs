using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Authentication.Social;

/// <summary>
/// Maps <see cref="UserAlert"/> and the indexes its two queries need.
/// </summary>
internal sealed class UserAlertConfiguration : IEntityTypeConfiguration<UserAlert>
{
    public void Configure(EntityTypeBuilder<UserAlert> builder)
    {
        builder.ToTable("UserAlerts");

        builder.HasKey(a => a.Id);

        builder.Property(a => a.RecipientUserId).HasMaxLength(450).IsRequired();
        builder.Property(a => a.ActorUserId).HasMaxLength(450);
        builder.Property(a => a.AlertType).HasMaxLength(128).IsRequired();
        builder.Property(a => a.RelatedContentType).HasMaxLength(128);
        builder.Property(a => a.CreatedAt).IsRequired();

        // Every alert query starts with "whose?", so every index does too. That is not just
        // for speed: it is the shape of the only question this table is ever asked, because
        // one user's alerts are never anyone else's business.
        //
        // Id descending gives newest-first straight from the index, and is the pagination
        // cursor.
        builder
            .HasIndex(a => new { a.RecipientUserId, a.Id })
            .IsDescending(false, true)
            .HasDatabaseName("IX_UserAlerts_RecipientUserId_Id");

        // The unread badge, asked on every page load by every user. Filtered so the index
        // holds only unread rows: an account with ten years of read alerts and three unread
        // ones scans three rows, not ten years.
        builder
            .HasIndex(a => new { a.RecipientUserId, a.IsRead })
            .HasFilter(null)
            .HasDatabaseName("IX_UserAlerts_RecipientUserId_IsRead");

        // Finding an existing alert to group onto, or to avoid raising twice: "has this actor
        // already been reported liking this content?"
        builder
            .HasIndex(a => new { a.RecipientUserId, a.AlertType, a.RelatedContentType, a.RelatedContentId })
            .HasDatabaseName("IX_UserAlerts_Recipient_Type_Content");
    }
}
