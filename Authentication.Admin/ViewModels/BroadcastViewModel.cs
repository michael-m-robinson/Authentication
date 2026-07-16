using System.ComponentModel.DataAnnotations;
using Authentication.Social;

namespace Authentication.Admin.ViewModels;

/// <summary>
/// The broadcast form: send an alert of any type, with optional literal text, to every user.
/// </summary>
public sealed class BroadcastViewModel
{
    /// <summary>
    /// The alert type to send. Any string: a built-in <see cref="AlertTypes"/> value, or a
    /// constant the host defines. Defaults to <see cref="AlertTypes.SystemAnnouncement"/>.
    /// </summary>
    [Required, StringLength(128)]
    public string AlertType { get; set; } = AlertTypes.SystemAnnouncement;

    /// <summary>
    /// Optional literal text for a one-off announcement whose wording is not derivable from the
    /// type. Left blank, the host renders the wording from <see cref="AlertType"/>.
    /// </summary>
    [StringLength(1024)]
    public string? Message { get; set; }

    /// <summary>Optional host content type the announcement points at.</summary>
    [StringLength(128)]
    public string? RelatedContentType { get; set; }

    /// <summary>Optional id within <see cref="RelatedContentType"/>.</summary>
    public long? RelatedContentId { get; set; }

    /// <summary>The built-in types, offered as suggestions in the form.</summary>
    public static IReadOnlyList<string> SuggestedTypes { get; } =
    [
        AlertTypes.SystemAnnouncement,
        AlertTypes.ContentModerated,
    ];
}
