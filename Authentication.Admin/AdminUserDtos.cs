namespace Authentication.Admin;

/// <summary>
/// A request for a page of users: an optional search term and where in the list to look.
/// </summary>
/// <param name="Search">
/// Case-insensitive substring matched against email and user name. Null or blank returns all
/// users.
/// </param>
/// <param name="Page">1-based page number. Values below 1 are treated as 1.</param>
/// <param name="PageSize">
/// Users per page. Clamped to a sensible range by the service so a caller cannot ask for the
/// whole table in one query.
/// </param>
public sealed record AdminUserQuery(string? Search = null, int Page = 1, int PageSize = 25);

/// <summary>
/// One user as the list shows them: enough to identify and triage, no more.
/// </summary>
/// <remarks>
/// Deliberately lean. Roles are not included here, because loading each user's roles for a
/// whole page would be a query per row; the roles appear on <see cref="AdminUserDetail"/>,
/// which is loaded one user at a time.
/// </remarks>
/// <param name="Id">The Identity user id.</param>
/// <param name="Email">The email address, or null if the user has none.</param>
/// <param name="EmailConfirmed">Whether the email has been confirmed.</param>
/// <param name="LockedOut">Whether the user is locked out right now.</param>
/// <param name="TwoFactorEnabled">Whether two-factor is enabled on the account.</param>
public sealed record AdminUserSummary(
    string Id,
    string? Email,
    bool EmailConfirmed,
    bool LockedOut,
    bool TwoFactorEnabled);

/// <summary>
/// The full read model for one user's detail page.
/// </summary>
/// <param name="Id">The Identity user id.</param>
/// <param name="Email">The email address, or null.</param>
/// <param name="EmailConfirmed">Whether the email has been confirmed.</param>
/// <param name="PhoneNumber">The phone number, or null. Never verified by this library.</param>
/// <param name="LockoutEnabled">Whether lockout policy applies to this account at all.</param>
/// <param name="LockoutEnd">When the current lockout ends, or null if not locked.</param>
/// <param name="LockedOutNow">Whether the user is locked out at this moment.</param>
/// <param name="TwoFactorEnabled">Whether two-factor is enabled.</param>
/// <param name="RecoveryCodesRemaining">How many two-factor recovery codes are left.</param>
/// <param name="Roles">The roles the user holds.</param>
public sealed record AdminUserDetail(
    string Id,
    string? Email,
    bool EmailConfirmed,
    string? PhoneNumber,
    bool LockoutEnabled,
    DateTimeOffset? LockoutEnd,
    bool LockedOutNow,
    bool TwoFactorEnabled,
    int RecoveryCodesRemaining,
    IReadOnlyList<string> Roles);

/// <summary>
/// A page of users, with the paging metadata a list view needs.
/// </summary>
/// <param name="Users">The users on this page.</param>
/// <param name="Page">The 1-based page number this represents.</param>
/// <param name="PageSize">The page size used.</param>
/// <param name="TotalCount">The total number of users matching the search.</param>
/// <param name="Search">The search term this page was produced for, echoed back for the view.</param>
public sealed record AdminUserPage(
    IReadOnlyList<AdminUserSummary> Users,
    int Page,
    int PageSize,
    int TotalCount,
    string? Search)
{
    /// <summary>
    /// The total number of pages for <see cref="TotalCount"/> at <see cref="PageSize"/>, at
    /// least 1.
    /// </summary>
    public int TotalPages => TotalCount <= 0 ? 1 : (int)Math.Ceiling(TotalCount / (double)PageSize);

    /// <summary>Whether a previous page exists.</summary>
    public bool HasPrevious => Page > 1;

    /// <summary>Whether a next page exists.</summary>
    public bool HasNext => Page < TotalPages;
}

/// <summary>
/// The outcome of an admin password reset.
/// </summary>
/// <remarks>
/// When the admin did not supply a password, the service generates one that satisfies the
/// configured policy and returns it here to be shown to the admin <em>once</em>. It is carried
/// in this result and rendered a single time; it is never logged, per the library's
/// no-secrets-in-logs rule.
/// </remarks>
/// <param name="Succeeded">Whether the password was changed.</param>
/// <param name="GeneratedPassword">
/// The generated password to display once, or null when the admin supplied their own or the
/// reset failed.
/// </param>
/// <param name="Errors">Any policy or store errors when the reset failed.</param>
public sealed record AdminPasswordResetResult(
    bool Succeeded,
    string? GeneratedPassword,
    IReadOnlyList<string> Errors);
