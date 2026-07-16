namespace Authentication.Social;

/// <summary>
/// Something that happened, which one user should be told about.
/// </summary>
/// <remarks>
/// Holds facts, not sentences. There is no <c>Message</c> and no <c>Html</c> here on purpose:
/// a stored sentence is frozen in the language and wording it was written in, so it cannot be
/// translated later, cannot be re-worded without rewriting history, and would let whatever
/// raised the alert put markup in front of a reader. The host turns
/// <see cref="AlertType"/> and the ids into something to read, at the moment it reads them.
/// </remarks>
public sealed class UserAlert
{
    /// <summary>
    /// The row's key, and the pagination cursor.
    /// </summary>
    /// <remarks>
    /// Ordering by this descending gives newest-first, because the database hands them out in
    /// ascending order. It beats paging by timestamp: two alerts raised in the same tick would
    /// make a timestamp cursor either skip one or repeat it.
    /// </remarks>
    public long Id { get; set; }

    /// <summary>
    /// The Identity user being told. Their alerts are theirs alone.
    /// </summary>
    public required string RecipientUserId { get; set; }

    /// <summary>
    /// The Identity user who caused it, if a person did.
    /// </summary>
    /// <remarks>
    /// Null for anything the system raised on its own, such as an announcement. Only ever an
    /// id: a display name or an email address stored here would be a copy that goes stale the
    /// moment the actor changes theirs, and would put one user's address in another user's
    /// table.
    /// </remarks>
    public string? ActorUserId { get; set; }

    /// <summary>
    /// What happened, as a stable name. See <see cref="AlertTypes"/>.
    /// </summary>
    /// <remarks>
    /// A name like <c>ContentLiked</c>, never the sentence shown to the user. The sentence is
    /// a rendering of this, and rendering changes.
    /// </remarks>
    public required string AlertType { get; set; }

    /// <summary>
    /// The content it concerns, if any.
    /// </summary>
    public string? RelatedContentType { get; set; }

    /// <summary>
    /// The id of the content it concerns, within <see cref="RelatedContentType"/>.
    /// </summary>
    public long? RelatedContentId { get; set; }

    /// <summary>
    /// Whether the recipient has read it.
    /// </summary>
    public bool IsRead { get; set; }

    /// <summary>
    /// When it was raised.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// When it was read, or null if it has not been.
    /// </summary>
    /// <remarks>
    /// Redundant against <see cref="IsRead"/>, and kept anyway: the flag answers "is there
    /// anything new", which is the question asked on every page load, and the timestamp
    /// answers "when", which is worth having and cannot be recovered from a boolean. The two
    /// are only ever set together.
    /// </remarks>
    public DateTimeOffset? ReadAt { get; set; }
}

/// <summary>
/// The alert types this package raises, and the ones a host is likely to want.
/// </summary>
/// <remarks>
/// Names, not messages. They are written to the database and read back for years, so they are
/// stable: renaming one orphans every alert already stored under the old name.
/// <para>
/// Constants rather than an enum, deliberately. A host will have alert types of its own that
/// this package has never heard of, and an enum would make those second-class - either
/// unrepresentable, or smuggled through a cast. A string column takes anyone's names equally.
/// </para>
/// </remarks>
public static class AlertTypes
{
    /// <summary>Someone liked the recipient's content. Raised by <see cref="ILikeService"/>.</summary>
    public const string ContentLiked = "ContentLiked";

    /// <summary>Someone commented on the recipient's content. Raised by the host.</summary>
    public const string ContentCommented = "ContentCommented";

    /// <summary>Someone replied to the recipient's comment. Raised by the host.</summary>
    public const string CommentReplied = "CommentReplied";

    /// <summary>A moderator changed the status of the recipient's content. Raised by the host.</summary>
    public const string ContentModerated = "ContentModerated";

    /// <summary>Something the recipient needs to know, from the system rather than a person.</summary>
    public const string SystemAnnouncement = "SystemAnnouncement";
}
