using System.ComponentModel.DataAnnotations;

namespace Authentication.Admin.ViewModels;

/// <summary>
/// The first-admin setup form: create a new administrator, or promote an existing user to
/// administrator.
/// </summary>
/// <remarks>
/// Client-side hints only. The server re-validates everything, and the real password policy is
/// enforced by the library when the account is created.
/// </remarks>
public sealed class SetupViewModel
{
    /// <summary>The email of the administrator to create or promote.</summary>
    [Required, EmailAddress]
    public string Email { get; set; } = "";

    /// <summary>
    /// The password for a new administrator. Ignored when <see cref="PromoteExisting"/> is set,
    /// because an existing user already has one.
    /// </summary>
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    /// <summary>
    /// When set, <see cref="Email"/> must name a user who already exists, and they are granted
    /// the admin role. When clear, a new account is created from <see cref="Email"/> and
    /// <see cref="Password"/>.
    /// </summary>
    public bool PromoteExisting { get; set; }

    /// <summary>
    /// The setup secret, required only when the host configured
    /// <see cref="AdminOptions.SetupToken"/>. Left blank otherwise.
    /// </summary>
    public string? SetupToken { get; set; }
}
