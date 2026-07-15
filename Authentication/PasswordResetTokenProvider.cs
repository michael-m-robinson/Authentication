// Adapted from the ASP.NET Core documentation sample "Change the email token lifespan":
// https://learn.microsoft.com/en-us/aspnet/core/security/authentication/accconfirm
// Licensed under the MIT License. Copyright (c) Microsoft Corporation.
// See THIRD-PARTY-NOTICES.txt.
//
// Changes from the original: this isolates the password-reset token rather than the
// email-confirmation token; both types are internal and sealed per rules/code-quality.md;
// and the lifespan comes from ReusableAuthOptions instead of being hard-coded in the
// options constructor.

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Authentication;

/// <summary>
/// Options for the password-reset token provider, kept separate from Identity's default
/// so reset tokens can expire on their own schedule.
/// </summary>
/// <remarks>
/// Identity points <c>EmailConfirmationTokenProvider</c>, <c>PasswordResetTokenProvider</c>
/// and <c>ChangeEmailTokenProvider</c> at one shared "Default" provider, so its single
/// <c>TokenLifespan</c> governs all three at once. Giving reset its own provider is the
/// only way to make a reset link expire sooner than a confirmation link.
/// </remarks>
internal sealed class PasswordResetTokenProviderOptions : DataProtectionTokenProviderOptions
{
    public PasswordResetTokenProviderOptions()
    {
        // Name is the data-protection purpose string, not a label: it scopes the
        // protector's keys, so a token minted here cannot be unprotected by the default
        // provider. Defence in depth - the token payload already carries and checks its
        // own purpose - but free.
        Name = "ReusableAuthPasswordResetTokenProvider";

        // Overwritten from ReusableAuthOptions.PasswordResetTokenLifetime at startup;
        // this is only the fallback if nothing configures it.
        TokenLifespan = TimeSpan.FromHours(1);
    }
}

/// <summary>
/// The password-reset token provider. Identical to Identity's default provider except
/// that it reads <see cref="PasswordResetTokenProviderOptions"/>, giving reset tokens a
/// lifetime of their own.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// <see cref="IOptions{TOptions}"/> is covariant, which is what lets
/// <see cref="PasswordResetTokenProviderOptions"/> satisfy the base class's
/// <c>IOptions&lt;DataProtectionTokenProviderOptions&gt;</c> parameter without a cast.
/// </remarks>
internal sealed class PasswordResetTokenProvider<TUser> : DataProtectorTokenProvider<TUser>
    where TUser : class
{
    public PasswordResetTokenProvider(
        IDataProtectionProvider dataProtectionProvider,
        IOptions<PasswordResetTokenProviderOptions> options,
        ILogger<DataProtectorTokenProvider<TUser>> logger)
        : base(dataProtectionProvider, options, logger)
    {
    }
}
