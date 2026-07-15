using Microsoft.AspNetCore.Identity;

namespace Authentication;

/// <summary>
/// The minimal built-in user type, used by
/// <c>AddReusableAuth()</c> when the host does not supply one of its own.
/// </summary>
/// <remarks>
/// This adds nothing beyond the fields ASP.NET Core Identity already defines. A
/// host that needs extra claims or columns should declare its own type deriving
/// from <see cref="IdentityUser"/> and call <c>AddReusableAuth&lt;TUser&gt;()</c>
/// instead; this type is sealed because extending it buys nothing over deriving
/// from <see cref="IdentityUser"/> directly.
/// </remarks>
public sealed class ReusableAuthUser : IdentityUser
{
}
