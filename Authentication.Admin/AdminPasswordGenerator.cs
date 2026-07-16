using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Admin;

/// <summary>
/// Generates a random password that satisfies a <see cref="PasswordOptions"/> policy, for the
/// admin password-reset flow when the administrator does not supply one.
/// </summary>
/// <remarks>
/// ASP.NET Core Identity ships no password generator, so this is a small, focused, tested piece
/// rather than logic buried in the user service. It draws every character from
/// <see cref="RandomNumberGenerator"/> (a cryptographic source) - the framework primitive, not
/// a hand-rolled one - and guarantees at least one character from each class the policy
/// requires, so the result passes Identity's own validators.
/// <para>
/// Ambiguous glyphs (<c>0/O</c>, <c>1/l/I</c>) are left out of the pools: an admin reads this
/// password aloud or types it once, and the confusion is not worth the handful of lost bits
/// against a 16-plus character random string.
/// </para>
/// </remarks>
internal static class AdminPasswordGenerator
{
    private const string Lowercase = "abcdefghijkmnpqrstuvwxyz";
    private const string Uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Digits = "23456789";
    private const string NonAlphanumeric = "!@#$%^&*-_=+?";

    // Comfortably above the library's 12-character default so the result clears the policy with
    // room to spare, whatever the host tuned it to.
    private const int MinimumLength = 16;

    /// <summary>
    /// Generates a password satisfying <paramref name="policy"/>.
    /// </summary>
    public static string Generate(PasswordOptions policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        List<char> required = new();
        StringBuilder pool = new();

        AddClass(policy.RequireLowercase, Lowercase, required, pool);
        AddClass(policy.RequireUppercase, Uppercase, required, pool);
        AddClass(policy.RequireDigit, Digits, required, pool);
        AddClass(policy.RequireNonAlphanumeric, NonAlphanumeric, required, pool);

        // A policy that requires no character class still needs something to draw from.
        if (pool.Length == 0)
        {
            pool.Append(Lowercase).Append(Uppercase).Append(Digits);
        }

        int length = Math.Max(Math.Max(policy.RequiredLength, MinimumLength), required.Count);
        char[] result = new char[length];

        // The guaranteed characters (one per required class) go in first.
        required.CopyTo(result);

        // Fill the rest from the pool. RandomNumberGenerator.GetItems is the .NET 8 official
        // primitive for an unbiased random draw with replacement from a set - it replaces a
        // hand-rolled pick-in-a-loop.
        if (length > required.Count)
        {
            RandomNumberGenerator.GetItems<char>(
                pool.ToString().AsSpan(),
                result.AsSpan(required.Count));
        }

        // RandomNumberGenerator.Shuffle is the official unbiased in-place shuffle, so the
        // guaranteed characters are not stuck at the front in a fixed order.
        RandomNumberGenerator.Shuffle<char>(result);
        return new string(result);
    }

    // Adds one guaranteed character of the class and folds the class into the fill pool.
    private static void AddClass(bool required, string characters, List<char> guaranteed, StringBuilder pool)
    {
        if (!required)
        {
            return;
        }

        // A single unbiased pick from this class (discard-and-retry, no modulo bias).
        guaranteed.Add(characters[RandomNumberGenerator.GetInt32(characters.Length)]);
        pool.Append(characters);
    }
}
