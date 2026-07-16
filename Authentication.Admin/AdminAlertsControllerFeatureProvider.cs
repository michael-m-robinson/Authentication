using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Authentication.Admin;

/// <summary>
/// Removes the admin alerts controller from the set of activatable controllers when the Social
/// features are not enabled, so it cannot be reached on a host that never wired
/// <c>Authentication.Social</c>.
/// </summary>
/// <remarks>
/// The alerts controller depends on <c>IAlertService</c>, which only exists when the host wired
/// Social. Shipping the controller unconditionally would mean a host without Social exposes a
/// <c>/admin/alerts</c> route that throws when it cannot resolve that service. Rather than let
/// the type ship and fail, this provider takes it out of the controller feature entirely when
/// alerts are off, so the route simply does not exist. The type still compiles into the
/// assembly; it is just never activated.
/// <para>
/// It matches by assembly and type name rather than by <c>typeof</c> so this infrastructure
/// piece carries no compile-time dependency on the controller, and it can only ever remove this
/// assembly's own controller, never a host's.
/// </para>
/// </remarks>
internal sealed class AdminAlertsControllerFeatureProvider : IApplicationFeatureProvider<ControllerFeature>
{
    // Both the MVC alerts controller and its JSON API twin depend on Social, so both come out
    // together when it is absent.
    internal static readonly string[] AlertsControllerTypeNames =
        ["AdminAlertsController", "AdminApiAlertsController"];

    private static readonly Assembly AdminAssembly =
        typeof(AdminAlertsControllerFeatureProvider).Assembly;

    private readonly bool _alertsEnabled;

    public AdminAlertsControllerFeatureProvider(bool alertsEnabled)
    {
        _alertsEnabled = alertsEnabled;
    }

    public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
    {
        ArgumentNullException.ThrowIfNull(feature);

        if (_alertsEnabled)
        {
            return;
        }

        for (int i = feature.Controllers.Count - 1; i >= 0; i--)
        {
            TypeInfo controller = feature.Controllers[i];
            if (controller.Assembly == AdminAssembly && AlertsControllerTypeNames.Contains(controller.Name))
            {
                feature.Controllers.RemoveAt(i);
            }
        }
    }
}
