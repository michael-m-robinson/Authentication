namespace Authentication.Social;

/// <summary>
/// Where a piece of content stands for one user.
/// </summary>
/// <param name="IsLiked">Whether this user's like is in place.</param>
/// <param name="LikeCount">
/// How many likes the content has, or <see langword="null"/> if it is not available to this
/// user. Counted from the database, never from anything the caller said.
/// </param>
/// <remarks>
/// <strong>The count carries availability.</strong> A number means the content is there and
/// this user may have it; <see langword="null"/> means they may not, and says nothing about
/// why. Note that <c>0</c> is an ordinary number here: content nobody has liked yet is
/// perfectly available, and reads as <c>LikeCount = 0</c>, not null.
/// <para>
/// Null covers content that does not exist, was deleted, is hidden, is not this user's to
/// see, and content that simply does not take likes. They are deliberately one answer.
/// Telling "no such thing" apart from "not for you" would let a caller walk the ids and map
/// out content they are not allowed to read, so the cases are folded together and the count
/// is withheld with them. A real count would give the same game away by another route: "5
/// likes" proves the content exists just as surely as an error message naming it would.
/// </para>
/// <para>
/// The same type answers "like it", "unlike it" and "how do things stand", because all three
/// have the same answer: is it liked, and by how many.
/// </para>
/// </remarks>
public sealed record LikeResult(bool IsLiked, int? LikeCount)
{
    /// <summary>
    /// Whether the content was available to this user, which is to say whether
    /// <see cref="LikeCount"/> has a value.
    /// </summary>
    /// <remarks>
    /// A host typically maps <see langword="false"/> to a 404 and leaves it there. Anything
    /// more specific would be inventing a distinction this type refuses to make.
    /// </remarks>
    public bool ContentAvailable => LikeCount.HasValue;

    /// <summary>
    /// The like is in place, and the content has <paramref name="likeCount"/> likes.
    /// </summary>
    internal static LikeResult Liked(int likeCount) => new(true, likeCount);

    /// <summary>
    /// The like is not in place, and the content has <paramref name="likeCount"/> likes.
    /// </summary>
    internal static LikeResult NotLiked(int likeCount) => new(false, likeCount);

    /// <summary>
    /// The content is not this user's to have, and no reason is given.
    /// </summary>
    /// <remarks>
    /// Used for missing, deleted, hidden and unauthorised content alike, and for content
    /// that does not take likes. The last of those could safely have been told apart - a
    /// user looking at content can see for themselves whether it has a like button - but it
    /// shares this answer so there is exactly one path out of here, and no later change can
    /// widen it into an oracle by accident.
    /// </remarks>
    internal static LikeResult Unavailable() => new(false, null);
}
