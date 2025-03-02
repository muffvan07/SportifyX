using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Domain.Helpers;
using SportifyX.Domain.Settings;

namespace SportifyX.Infrastructure.Middleware
{
    public class ApiKeyMiddleware(RequestDelegate next, IOptions<ApiSettings> options)
    {
        private readonly RequestDelegate _next = next;
        private readonly ApiSettings _apiSettings = options.Value;

        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.Request.Headers.TryGetValue("X-API-KEY", out var extractedApiKey))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("MissingApiKeyErrorMessage"));

                await context.Response.WriteAsync(JsonConvert.SerializeObject(errorResponse));
                return;
            }

            if (_apiSettings.ApiKey != extractedApiKey)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("InvalidApiKeyErrorMessage"));

                await context.Response.WriteAsync(JsonConvert.SerializeObject(errorResponse));
                return;
            }

            await _next(context);
        }
    }
}
