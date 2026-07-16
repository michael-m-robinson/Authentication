namespace Authentication.Social;

/// <summary>
/// Tells this package what a piece of content is. Implemented by the host.
/// </summary>
/// <remarks>
/// This exists because a reusable library cannot know what content is. Before storing a like
/// the package has to establish that the target exists, that it accepts likes, that the user
/// is allowed to see it, and who owns it so an alert can be raised. Every one of those is a
/// question about the host's own domain, and only the host can answer it.
/// <para>
/// It is called on the like path, so keep it quick and cache if you need to. It is not
/// called on unlike: a user removing their own like should not be blocked because the
/// content has since been deleted or hidden from them.
/// </para>
/// </remarks>
public interface IContentSource
{
    /// <summary>
    /// Describes a piece of content as far as <paramref name="userId"/> is concerned, or
    /// <see langword="null"/> if they cannot have it.
    /// </summary>
    /// <param name="userId">The Identity user asking.</param>
    /// <param name="contentType">The host's own type name, e.g. <c>Article</c>.</param>
    /// <param name="contentId">The id within that type.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>The content, or <see langword="null"/>.</returns>
    /// <remarks>
    /// <strong>Return <see langword="null"/> for anything this user cannot have</strong>:
    /// content that does not exist, was deleted, is hidden, is a draft, or simply is not
    /// theirs to see. Do not distinguish between them.
    /// <para>
    /// That is the whole design of this method. If "no such thing" and "not for you" gave
    /// different answers, the like endpoint would become a way to ask whether a given id
    /// exists, and a caller could walk the ids to map out content they are not allowed to
    /// read. One answer for both leaves nothing to learn. It is the same reasoning that
    /// makes a failed sign-in in the core package refuse to say which part was wrong.
    /// </para>
    /// <para>
    /// Throwing is not the way to refuse. A <see langword="null"/> is an ordinary answer
    /// that the caller turns into an ordinary result; an exception would surface to the host
    /// as a fault.
    /// </para>
    /// </remarks>
    Task<ContentInfo?> GetAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken);
}

/// <summary>
/// What this package needs to know about a piece of content.
/// </summary>
/// <param name="OwnerUserId">
/// The Identity user who owns it. Used to decide who to alert, and to recognise a user
/// liking their own content so they are not alerted about themselves. Pass an empty string
/// if the content genuinely has no owner, such as a system announcement.
/// </param>
/// <param name="SupportsLikes">
/// Whether this content accepts likes at all. Defaults to <see langword="false"/>: content
/// is not likeable until the host says it is.
/// </param>
/// <remarks>
/// Deliberately small. Everything else about the content - its title, body, author name,
/// URL - belongs to the host, and this package has no use for it. Passing more would put
/// the host's data through a library that only needs to know who to tell.
/// <para>
/// <strong>Likes are opt-in per content item.</strong> <c>new ContentInfo(ownerId)</c>
/// refuses likes; you have to write <c>new ContentInfo(ownerId, SupportsLikes: true)</c> to
/// allow them. The default is the safe direction rather than the convenient one: a host that
/// adds a new content type and forgets this gets content nobody can like, which is visible
/// and harmless, instead of content that accepts likes it was never meant to have.
/// </para>
/// </remarks>
public sealed record ContentInfo(string OwnerUserId, bool SupportsLikes = false);
