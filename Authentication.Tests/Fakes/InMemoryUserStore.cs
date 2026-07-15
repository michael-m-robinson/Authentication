using System.Collections.Concurrent;
using Authentication;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Tests.Fakes;

/// <summary>
/// A working in-memory Identity store: enough of the interfaces for register, sign-in,
/// email confirmation, password reset and security-stamp rotation to run for real.
/// </summary>
/// <remarks>
/// Implements <see cref="IUserSecurityStampStore{TUser}"/>, without which Identity's stamp
/// checks silently pass and the rotation tests would prove nothing.
/// </remarks>
internal sealed class InMemoryUserStore :
    IUserStore<ReusableAuthUser>,
    IUserPasswordStore<ReusableAuthUser>,
    IUserEmailStore<ReusableAuthUser>,
    IUserSecurityStampStore<ReusableAuthUser>,
    IUserLockoutStore<ReusableAuthUser>
{
    private readonly ConcurrentDictionary<string, ReusableAuthUser> _users = new(StringComparer.Ordinal);

    public IReadOnlyCollection<ReusableAuthUser> Users => _users.Values.ToList();

    public Task<IdentityResult> CreateAsync(ReusableAuthUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(
            _users.TryAdd(user.Id, user)
                ? IdentityResult.Success
                : IdentityResult.Failed(new IdentityError { Code = "DuplicateId" }));
    }

    public Task<IdentityResult> UpdateAsync(ReusableAuthUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        _users[user.Id] = user;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(ReusableAuthUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        _users.TryRemove(user.Id, out _);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<ReusableAuthUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        => Task.FromResult(_users.GetValueOrDefault(userId));

    public Task<ReusableAuthUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        => Task.FromResult(_users.Values.FirstOrDefault(
            u => string.Equals(u.NormalizedUserName, normalizedUserName, StringComparison.Ordinal)));

    public Task<ReusableAuthUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        => Task.FromResult(_users.Values.FirstOrDefault(
            u => string.Equals(u.NormalizedEmail, normalizedEmail, StringComparison.Ordinal)));

    public Task<string> GetUserIdAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.Id);

    public Task<string?> GetUserNameAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.UserName);

    public Task SetUserNameAsync(ReusableAuthUser user, string? userName, CancellationToken cancellationToken)
    {
        user.UserName = userName;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedUserNameAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.NormalizedUserName);

    public Task SetNormalizedUserNameAsync(ReusableAuthUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public Task SetPasswordHashAsync(ReusableAuthUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    public Task<string?> GetPasswordHashAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.PasswordHash);

    public Task<bool> HasPasswordAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.PasswordHash is not null);

    public Task SetEmailAsync(ReusableAuthUser user, string? email, CancellationToken cancellationToken)
    {
        user.Email = email;
        return Task.CompletedTask;
    }

    public Task<string?> GetEmailAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.Email);

    public Task<bool> GetEmailConfirmedAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.EmailConfirmed);

    public Task SetEmailConfirmedAsync(ReusableAuthUser user, bool confirmed, CancellationToken cancellationToken)
    {
        user.EmailConfirmed = confirmed;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedEmailAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.NormalizedEmail);

    public Task SetNormalizedEmailAsync(ReusableAuthUser user, string? normalizedEmail, CancellationToken cancellationToken)
    {
        user.NormalizedEmail = normalizedEmail;
        return Task.CompletedTask;
    }

    public Task SetSecurityStampAsync(ReusableAuthUser user, string stamp, CancellationToken cancellationToken)
    {
        user.SecurityStamp = stamp;
        return Task.CompletedTask;
    }

    public Task<string?> GetSecurityStampAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.SecurityStamp);

    public Task<DateTimeOffset?> GetLockoutEndDateAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.LockoutEnd);

    public Task SetLockoutEndDateAsync(ReusableAuthUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        user.LockoutEnd = lockoutEnd;
        return Task.CompletedTask;
    }

    public Task<int> IncrementAccessFailedCountAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(++user.AccessFailedCount);

    public Task ResetAccessFailedCountAsync(ReusableAuthUser user, CancellationToken cancellationToken)
    {
        user.AccessFailedCount = 0;
        return Task.CompletedTask;
    }

    public Task<int> GetAccessFailedCountAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.AccessFailedCount);

    public Task<bool> GetLockoutEnabledAsync(ReusableAuthUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.LockoutEnabled);

    public Task SetLockoutEnabledAsync(ReusableAuthUser user, bool enabled, CancellationToken cancellationToken)
    {
        user.LockoutEnabled = enabled;
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        // Nothing to release.
    }
}
