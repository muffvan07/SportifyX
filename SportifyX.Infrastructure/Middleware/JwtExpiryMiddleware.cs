using Microsoft.AspNetCore.Http;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Domain.Helpers;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace SportifyX.Infrastructure.Middleware
{
    public class JwtExpiryMiddleware(RequestDelegate next)
    {
        public async Task InvokeAsync(HttpContext context)
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
            options.Converters.Add(new JsonDateTimeConverter());

            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var token = authHeader.Substring("Bearer ".Length).Trim();

                var handler = new JwtSecurityTokenHandler();

                try
                {
                    if (handler.ReadToken(token) is JwtSecurityToken jwtToken)
                    {
                        var exp = jwtToken.ValidTo;
                        if (exp < DateTime.UtcNow)
                        {
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                            context.Response.ContentType = "application/json";
                            var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("TokenExpiredErrorMessage"));
                            
                            await context.Response.WriteAsync(JsonSerializer.Serialize(errorResponse, options));
                            return;
                        }
                    }
                }
                catch
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";
                    var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("InvalidTokenErrorMessage"));
                    
                    await context.Response.WriteAsync(JsonSerializer.Serialize(errorResponse, options));
                    return;
                }
            }

            await next(context);
        }
    }
}