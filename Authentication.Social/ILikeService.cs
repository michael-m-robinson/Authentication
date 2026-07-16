namespace Authentication.Social;

/// <summary>
/// Likes on content, keyed to the signed-in Identity user.
/// </summary>
/// <remarks>
/// Both changes are idempotent. Liking something already liked, or unliking something not
/// liked, is not an error: it is a request for a state that already holds, and the answer is
/// simply that state. Clients double-submit, retry and race, and none of that should produce
/// a failure the user has to understand.
/// <para>
/// Pass the user id from the authenticated request - <c>IAuthService.CurrentPrincipal</c>,
/// or the <c>NameIdentifier</c> claim. Never take it from the request body: a caller who
/// supplies their own id can like as anyone.
/// </para>
/// <para>
/// Every method asks <see cref="IContentSource"/>, so no count ever describes content the
/// caller may not see: content they may not have comes back with a null
/// <see cref="LikeResult.LikeCount"/> and no explanation. The one thing that does not depend
/// on that answer is removing a like, which is the caller's own row and is always theirs to
/// take back.
/// </para>
/// </remarks>
public interface ILikeService
{
    /// <summary>
    /// Likes a piece of content on behalf of a user.
    /// </summary>
    /// <param name="userId">The Identity user, from the authenticated request.</param>
    /// <param name="contentType">The host's own type name, e.g. <c>Article</c>.</param>
    /// <param name="contentId">The id within that type.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// Where the content stands for this user afterwards, or a null
    /// <see cref="LikeResult.LikeCount"/> if the content is not theirs to have.
    /// </returns>
    /// <remarks>
    /// Idempotent. A user who already likes it gets <see cref="LikeResult.IsLiked"/> true and
    /// the unchanged count, no second row, and no second alert.
    /// <para>
    /// Users may like their own content; the like counts like any other. No alert is raised
    /// for it, since nobody needs telling what they just did.
    /// </para>
    /// </remarks>
    Task<LikeResult> LikeAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes a user's own like.
    /// </summary>
    /// <param name="userId">The Identity user, from the authenticated request.</param>
    /// <param name="contentType">The host's own type name.</param>
    /// <param name="contentId">The id within that type.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// Where the content stands for this user afterwards, or a null
    /// <see cref="LikeResult.LikeCount"/> if the content is not theirs to have.
    /// </returns>
    /// <remarks>
    /// Idempotent. Unliking something not liked returns the unliked state rather than an
    /// error.
    /// <para>
    /// A user can only remove their own like, and that is structural rather than checked:
    /// the row is found by (user, content type, content id), so there is no id a caller could
    /// pass to reach someone else's like.
    /// </para>
    /// <para>
    /// <strong>The like is always removed, even if the content is no longer available to
    /// them.</strong> Nobody should be stuck holding a like on an article that has since been
    /// hidden. The count is another matter: it describes the content, not their own row, so
    /// when the content is unavailable it is withheld and
    /// <see cref="LikeResult.LikeCount"/> comes back null - the removal still happened.
    /// </para>
    /// </remarks>
    Task<LikeResult> UnlikeAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reports whether a user likes a piece of content, and how many likes it has.
    /// </summary>
    /// <param name="userId">The Identity user, from the authenticated request.</param>
    /// <param name="contentType">The host's own type name.</param>
    /// <param name="contentId">The id within that type.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// Where the content stands for this user, changing nothing, or a null
    /// <see cref="LikeResult.LikeCount"/> if the content is not theirs to have.
    /// </returns>
    /// <remarks>
    /// For rendering a like button in its right state. Changes nothing.
    /// <para>
    /// Access is still checked. Counting is a read, but an uncontrolled one would answer the
    /// question the like path refuses to: a count for content the user cannot see proves it
    /// exists.
    /// </para>
    /// </remarks>
    Task<LikeResult> GetAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken);
}
