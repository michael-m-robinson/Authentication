using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace Authentication.Admin;

/// <summary>
/// Prepends the configured route prefix (<c>admin</c> by default) to every controller in this
/// assembly, so the whole panel moves with one option.
/// </summary>
/// <remarks>
/// The admin controllers declare routes relative to the prefix (<c>[Route("users")]</c>,
/// <c>[Route("roles")]</c>, and <c>[Route("")]</c> for the dashboard). This convention combines
/// the prefix in front, turning them into <c>/admin/users</c>, <c>/admin/roles</c>,
/// <c>/admin</c>, and so on. It touches only controllers from this assembly, identified by
/// assembly, so a host's own controllers are left exactly as they were.
/// </remarks>
internal sealed class AdminRoutePrefixConvention : IApplicationModelConvention
{
    private static readonly System.Reflection.Assembly AdminAssembly =
        typeof(AdminRoutePrefixConvention).Assembly;

    private readonly AttributeRouteModel _prefix;

    public AdminRoutePrefixConvention(string routePrefix)
    {
        _prefix = new AttributeRouteModel(new RouteAttribute(routePrefix));
    }

    public void Apply(ApplicationModel application)
    {
        ArgumentNullException.ThrowIfNull(application);

        foreach (ControllerModel controller in application.Controllers)
        {
            if (controller.ControllerType.Assembly != AdminAssembly)
            {
                continue;
            }

            foreach (SelectorModel selector in controller.Selectors)
            {
                selector.AttributeRouteModel = selector.AttributeRouteModel is null
                    ? _prefix
                    : AttributeRouteModel.CombineAttributeRouteModel(_prefix, selector.AttributeRouteModel);
            }
        }
    }
}
