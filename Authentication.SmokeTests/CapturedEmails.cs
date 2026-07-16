using System.Collections.Concurrent;
using Authentication;

namespace Authentication.SmokeTests;

/// <summary>
/// The host's <see cref="IAuthEmailSender"/>, capturing instead of sending.
/// </summary>
/// <remarks>
/// A real host would build a link and post it to an SMTP provider. This keeps the pieces so
/// a test can follow the link the user would have clicked, which is the only way to drive
/// confirmation and reset end to end rather than reaching around them.
/// </remarks>
internal sealed class CapturedEmails : IAuthEmailSender
{
    private readonly ConcurrentBag<CapturedEmail> _sent = [];

    public IReadOnlyCollection<CapturedEmail> Sent => [.. _sent];

    public Task SendEmailConfirmationAsync(string email, string userId, string token)
    {
        _sent.Add(new CapturedEmail("confirmation", email, userId, token));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string email, string userId, string token)
    {
        _sent.Add(new CapturedEmail("reset", email, userId, token));
        return Task.CompletedTask;
    }

    public Task SendRegistrationAttemptedAsync(string email)
    {
        _sent.Add(new CapturedEmail("registration-attempted", email, null, null));
        return Task.CompletedTask;
    }

    /// <summary>
    /// Waits for an email of the given kind, since delivery is queued off the request.
    /// </summary>
    /// <remarks>
    /// Polls rather than assuming: the library hands auth emails to a background worker
    /// precisely so the request does not wait for them, which means an assertion made the
    /// instant the response arrives would race the worker and fail intermittently.
    /// </remarks>
    public async Task<CapturedEmail> WaitForAsync(string kind, string email, TimeSpan? timeout = null)
    {
        DateTime deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));

        while (DateTime.UtcNow < deadline)
        {
            CapturedEmail? found = _sent.FirstOrDefault(
                e => e.Kind == kind && string.Equals(e.Email, email, StringComparison.OrdinalIgnoreCase));

            if (found is not null)
            {
                return found;
            }

            await Task.Delay(25);
        }

        throw new TimeoutException(
            $"No '{kind}' email to {email} within the timeout. Captured: " +
            string.Join(", ", _sent.Select(e => $"{e.Kind}->{e.Email}")));
    }
}

internal sealed record CapturedEmail(string Kind, string Email, string? UserId, string? Token);
