using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Mgmt.Service.Services;

namespace User.Mgmt.Service.CustomMiddleware
{
    public class MiddlewareInterceptBlacklistToken
    {
        private readonly RequestDelegate _next;

        public MiddlewareInterceptBlacklistToken(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ITokenBlacklistService tokenManager)
        {
            // Extract token from Authorization header
            var authHeader = context.Request.Headers["Authorization"].ToString();

            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring("Bearer ".Length).Trim();

                var isTokenBlock = await tokenManager.IsTokenBlacklistedAsync(token);
                if (isTokenBlock is true)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;

                    await context.Response.WriteAsync("Token has been revoked/logged out.");

                    return; // Short-circuit the request pipeline
                }
            }
            await _next(context);
        }

    }
}
