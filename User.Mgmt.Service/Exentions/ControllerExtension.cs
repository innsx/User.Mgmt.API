using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace User.Mgmt.Service.Exentions
{
    public static class ControllerExtension
    {
        public static string GetBaseUrl(this ControllerBase controller)
        {
            var req = controller.Request;
            return $"{req.Scheme}://{req.Host}{req.PathBase}";
        }
    }
}
