namespace Authentication.Social;

/// <summary>
/// One user's like of one piece of content.
/// </summary>
/// <remarks>
/// A row exists only while the like does. Unliking deletes it rather than flagging it,
/// which is why there is no <c>IsDeleted</c> and no <c>UpdatedUtc</c>: a like holds nothing
/// editable, so there is no state to change and nothing to keep a history of.
/// <para>
/// The library never interprets <see cref="ContentType"/> or <see cref="ContentId"/>. They
/// identify something in the host's application, and only the host knows what that is or
/// who may see it.
/// </para>
/// </remarks>
public sealed class ContentLike
{
    /// <summary>
    /// The row's own key. Nothing outside this package should depend on it.
    /// </summary>
    /// <remarks>
    /// Deliberately not the identity of the like. A like <em>is</em>
    /// (<see cref="UserId"/>, <see cref="ContentType"/>, <see cref="ContentId"/>), and the
    /// unique index over those three is what enforces that. This is a surrogate key so the
    /// row is cheap to reference; it is not a second way to name the same like.
    /// </remarks>
    public long Id { get; set; }

    /// <summary>
    /// The Identity user who liked it.
    /// </summary>
    /// <remarks>
    /// The stable Identity user id, never a username or email address. Those change: a user
    /// changing their email through <c>IAccountService</c> would otherwise orphan every like
    /// they had ever made, and an address freed up and re-registered by someone else would
    /// inherit them.
    /// </remarks>
    public required string UserId { get; set; }

    /// <summary>
    /// The kind of thing liked, in the host's own vocabulary. For example <c>Article</c>.
    /// </summary>
    /// <remarks>
    /// Part of the key because ids are only unique within a type: <c>Article 42</c> and
    /// <c>Comment 42</c> are different things, and without this they would collide into one
    /// like.
    /// </remarks>
    public required string ContentType { get; set; }

    /// <summary>
    /// The id of the thing liked, within its <see cref="ContentType"/>.
    /// </summary>
    public long ContentId { get; set; }

    /// <summary>
    /// When the like was made.
    /// </summary>
    /// <remarks>
    /// <see cref="DateTimeOffset"/> rather than <see cref="DateTime"/>, matching
    /// <c>IdentityUser.LockoutEnd</c> in the very same <c>DbContext</c>. The difference is
    /// not cosmetic: a <see cref="DateTime"/> loses its <c>Kind</c> on the way through
    /// several providers - SQLite has no date type and hands back <c>Unspecified</c> - so a
    /// value saved as UTC returns as something the runtime will happily treat as local.
    /// A <see cref="DateTimeOffset"/> carries its offset, so a round trip cannot silently
    /// change what the value means.
    /// </remarks>
    public DateTimeOffset CreatedAt { get; set; }
}
