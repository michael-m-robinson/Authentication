using Authentication;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Tests.Fakes;

/// <summary>
/// A store that does NOT implement <see cref="IUserSecurityStampStore{TUser}"/>, which is
/// the shape that makes Identity's stamp check silently pass. Used to prove the startup
/// guard rejects it.
/// </summary>
internal sealed class StamplessUserStore : IUserStore<ReusableAuthUser>
{
    public Task<IdentityResult> CreateAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<IdentityResult> DeleteAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<ReusableAuthUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<ReusableAuthUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<string?> GetNormalizedUserNameAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<string> GetUserIdAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<string?> GetUserNameAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task SetNormalizedUserNameAsync(ReusableAuthUser user, string? normalizedName, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task SetUserNameAsync(ReusableAuthUser user, string? userName, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<IdentityResult> UpdateAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public void Dispose()
    {
        // Nothing to release.
    }
}

/// <summary>
/// A store that does implement <see cref="IUserSecurityStampStore{TUser}"/>, i.e. the
/// shape the library requires of a host.
/// </summary>
internal sealed class StampAwareUserStore : IUserStore<ReusableAuthUser>, IUserSecurityStampStore<ReusableAuthUser>
{
    public Task<IdentityResult> CreateAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<IdentityResult> DeleteAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<ReusableAuthUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<ReusableAuthUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<string?> GetNormalizedUserNameAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<string> GetUserIdAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<string?> GetUserNameAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task SetNormalizedUserNameAsync(ReusableAuthUser user, string? normalizedName, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task SetUserNameAsync(ReusableAuthUser user, string? userName, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<IdentityResult> UpdateAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<string?> GetSecurityStampAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult<string?>(user?.SecurityStamp);

    public Task SetSecurityStampAsync(ReusableAuthUser user, string stamp, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        user.SecurityStamp = stamp;
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        // Nothing to release.
    }
}
