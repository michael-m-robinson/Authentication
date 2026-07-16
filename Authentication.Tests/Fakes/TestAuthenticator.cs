using System.Net;
using System.Security.Cryptography;

namespace Authentication.Tests.Fakes;

/// <summary>
/// Computes TOTP codes from a shared key, exactly as a real authenticator app would.
/// </summary>
/// <remarks>
/// This exists because the server cannot do it. Identity's
/// <c>AuthenticatorTokenProvider.GenerateAsync</c> returns an empty string, deliberately,
/// since the whole point of the second factor is that the code comes from a device the
/// server does not have. So a test that wants to prove the key we hand out actually works
/// has to play the part of the phone.
/// <para>
/// RFC 6238 (TOTP) over RFC 4648 base32, HMAC-SHA1, 30-second steps, six digits: the
/// parameters Identity's provider validates against and the ones baked into the
/// <c>otpauth://</c> URI.
/// </para>
/// </remarks>
internal static class TestAuthenticator
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const int Digits = 1_000_000;
    private const long TimeStepSeconds = 30;

    /// <summary>
    /// The code an authenticator app would be showing right now for this key.
    /// </summary>
    /// <param name="base32Key">The raw shared key, as Identity stores it.</param>
    internal static string Generate(string base32Key)
    {
        byte[] key = FromBase32(base32Key);
        long timeStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / TimeStepSeconds;

        byte[] counter = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(timeStep));
        byte[] hash = HMACSHA1.HashData(key, counter);

        // Dynamic truncation, RFC 4226 §5.4.
        int offset = hash[^1] & 0x0F;
        int binary =
            ((hash[offset] & 0x7F) << 24)
            | ((hash[offset + 1] & 0xFF) << 16)
            | ((hash[offset + 2] & 0xFF) << 8)
            | (hash[offset + 3] & 0xFF);

        return (binary % Digits).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] FromBase32(string input)
    {
        ReadOnlySpan<char> trimmed = input.AsSpan().TrimEnd('=');

        List<byte> output = [];
        int buffer = 0;
        int bitsInBuffer = 0;

        foreach (char c in trimmed)
        {
            int value = Base32Alphabet.IndexOf(char.ToUpperInvariant(c));
            if (value < 0)
            {
                throw new ArgumentException($"'{c}' is not valid base32.", nameof(input));
            }

            buffer = (buffer << 5) | value;
            bitsInBuffer += 5;

            if (bitsInBuffer >= 8)
            {
                bitsInBuffer -= 8;
                output.Add((byte)(buffer >> bitsInBuffer));
                buffer &= (1 << bitsInBuffer) - 1;
            }
        }

        return [.. output];
    }
}
