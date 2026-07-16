using Microsoft.EntityFrameworkCore;

namespace Authentication.Social;

/// <summary>
/// Adds the social tables to a host's <see cref="DbContext"/> model.
/// </summary>
public static class SocialModelBuilderExtensions
{
    /// <summary>
    /// Configures <see cref="ContentLike"/> and its indexes on this model.
    /// </summary>
    /// <param name="modelBuilder">The model being built.</param>
    /// <returns>The same <paramref name="modelBuilder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="modelBuilder"/> is null.</exception>
    /// <remarks>
    /// Call this from your context's <c>OnModelCreating</c>, after <c>base.OnModelCreating</c>:
    /// <code>
    /// protected override void OnModelCreating(ModelBuilder modelBuilder)
    /// {
    ///     base.OnModelCreating(modelBuilder);      // the auth tables
    ///     modelBuilder.AddReusableAuthSocial();    // likes and alerts
    /// }
    /// </code>
    /// The social tables go on your existing context rather than one of their own, so a like
    /// and the alert it raises are written in the same transaction, as they must be: an alert
    /// about a like that was rolled back is a lie, and a like whose alert was lost is silent.
    /// </remarks>
    public static ModelBuilder AddReusableAuthSocial(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.ApplyConfiguration(new ContentLikeConfiguration());
        modelBuilder.ApplyConfiguration(new UserAlertConfiguration());

        return modelBuilder;
    }
}
