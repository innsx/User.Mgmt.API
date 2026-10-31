using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace User.Mgmt.Service.Models
{
    public class JwtSettings
    {
        public string? ValidAudience { get; set; }
        public string? ValidIssuer { get; set; }
        public string? Secret { get; set; }
        public int TokenValidationInMinutes { get; set; }
        public int RefreshTokenValidity { get; set; }
    }
}
