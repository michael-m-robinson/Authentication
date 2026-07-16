using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Admin.Tests;

/// <summary>
/// Covers <c>AdminPasswordGenerator</c>: that a generated password always satisfies the policy
/// it was built for, and in particular the library's real password validators.
/// </summary>
public sealed class AdminPasswordGeneratorTests
{
    private static PasswordOptions Policy(
        int length = 12,
        bool digit = true,
        bool lower = true,
        bool upper = true,
        bool nonAlnum = true) => new()
        {
            RequiredLength = length,
            RequireDigit = digit,
            RequireLowercase = lower,
            RequireUppercase = upper,
            RequireNonAlphanumeric = nonAlnum,
        };

    [Theory]
    [InlineData(12, true, true, true, true)]     // the library default
    [InlineData(8, true, true, true, false)]     // no symbol required
    [InlineData(24, false, true, false, false)]  // long, lowercase only
    [InlineData(16, false, false, false, false)] // no class required at all
    public void Generated_SatisfiesTheClassesThePolicyRequires(
        int length, bool digit, bool lower, bool upper, bool nonAlnum)
    {
        PasswordOptions policy = Policy(length, digit, lower, upper, nonAlnum);

        string password = AdminPasswordGenerator.Generate(policy);

        Assert.True(password.Length >= policy.RequiredLength);
        if (digit) Assert.Contains(password, char.IsDigit);
        if (lower) Assert.Contains(password, char.IsLower);
        if (upper) Assert.Contains(password, char.IsUpper);
        if (nonAlnum) Assert.Contains(password, c => !char.IsLetterOrDigit(c));
    }

    [Fact]
    public async Task Generated_PassesTheRealPasswordValidators()
    {
        // The ground truth: a password the generator produced for the app's actual policy must
        // be one the app will actually accept. Create a user with it and let Identity's own
        // validators judge.
        using AdminTestHost host = new();
        using IServiceScope scope = host.Scope();
        UserManager<ReusableAuthUser> users = scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        for (int i = 0; i < 25; i++)
        {
            string password = AdminPasswordGenerator.Generate(users.Options.Password);

            ReusableAuthUser user = new() { UserName = $"gen{i}@example.com", Email = $"gen{i}@example.com" };
            IdentityResult result = await users.CreateAsync(user, password);

            Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(e => e.Description)));
        }
    }

    [Fact]
    public void TwoGenerations_Differ()
    {
        PasswordOptions policy = Policy();
        Assert.NotEqual(AdminPasswordGenerator.Generate(policy), AdminPasswordGenerator.Generate(policy));
    }
}
