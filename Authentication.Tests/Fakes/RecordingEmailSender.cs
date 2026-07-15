using System.Collections.Concurrent;
using Authentication;

namespace Authentication.Tests.Fakes;

/// <summary>
/// Records what the library asked to have emailed, so tests can assert on it.
/// </summary>
/// <remarks>
/// The register flow's whole non-enumeration story rests on which message goes out — a
/// confirmation for a new address, a "someone tried to register" notice for a taken one —
/// so what lands here is the observable behaviour, not an implementation detail.
/// </remarks>
internal sealed class RecordingEmailSender : IAuthEmailSender
{
    public ConcurrentBag<SentEmail> Sent { get; } = [];

    public Task SendEmailConfirmationAsync(string email, string userId, string token)
    {
        Sent.Add(new SentEmail(EmailKind.Confirmation, email, userId, token));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string email, string userId, string token)
    {
        Sent.Add(new SentEmail(EmailKind.PasswordReset, email, userId, token));
        return Task.CompletedTask;
    }

    public Task SendRegistrationAttemptedAsync(string email)
    {
        Sent.Add(new SentEmail(EmailKind.RegistrationAttempted, email, UserId: null, Token: null));
        return Task.CompletedTask;
    }

    public IEnumerable<SentEmail> OfKind(EmailKind kind) => Sent.Where(e => e.Kind == kind);
}

internal enum EmailKind
{
    Confirmation,
    PasswordReset,
    RegistrationAttempted,
}

internal sealed record SentEmail(EmailKind Kind, string Email, string? UserId, string? Token);
