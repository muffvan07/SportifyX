using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Helpers;
using System.Diagnostics;

namespace SportifyX.Infrastructure.Middleware
{
    /// <summary>
    /// Middleware for global exception handling and logging.
    /// </summary>
    public class ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger, IServiceScopeFactory scopeFactory)
    {
        #region Variables

        /// <summary>
        /// The next
        /// </summary>
        private readonly RequestDelegate _next = next;

        /// <summary>
        /// The logger
        /// </summary>
        private readonly ILogger<ExceptionHandlingMiddleware> _logger = logger;

        /// <summary>
        /// The scope factory
        /// </summary>
        private readonly IServiceScopeFactory _scopeFactory = scopeFactory;

        #endregion

        #region Public Methods

        /// <summary>
        /// Invokes the middleware logic.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        public async Task Invoke(HttpContext context)
        {
            await ReadRequestBodyAsync(context);

            var correlationId = context.Request.Headers.TryGetValue("X-Correlation-ID", out var corrId)
                ? corrId.ToString()
                : Guid.NewGuid().ToString();

            context.Response.Headers["X-Correlation-ID"] = correlationId;

            var requestStartTime = DateTime.UtcNow;
            var stopwatch = Stopwatch.StartNew();

            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "An unhandled exception occurred. CorrelationId: {CorrelationId}", correlationId);

                using var scope = _scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<IExceptionHandlingService>();

                // Log exception with additional context
                await service.LogExceptionAsync(ex, context);

                await HandleExceptionAsync(context, ex, correlationId, requestStartTime, stopwatch.ElapsedMilliseconds);
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Handles the exception and writes a standardized error response.
        /// </summary>
        private static Task HandleExceptionAsync(HttpContext context, Exception ex, string correlationId, DateTime requestStartTime, long executionTimeMs)
        {
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;

            var response = ApiResponse<object>.Fail(context.Response.StatusCode, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
            
            return context.Response.WriteAsync(JsonConvert.SerializeObject(response));
        }

        /// <summary>
        /// Reads and optionally minifies the request body.
        /// </summary>
        private static async Task<string> ReadRequestBodyAsync(HttpContext context)
        {
            try
            {
                context.Request.EnableBuffering();
                using var reader = new StreamReader(context.Request.Body, System.Text.Encoding.UTF8, leaveOpen: true);
                var body = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;

                if (!string.IsNullOrWhiteSpace(body) && IsValidJson(body))
                {
                    body = JsonConvert.SerializeObject(JsonConvert.DeserializeObject(body), Formatting.None);
                }

                context.Items["RequestBody"] = body;
                return body;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Checks if a string is valid JSON.
        /// </summary>
        private static bool IsValidJson(string input)
        {
            try
            {
                JToken.Parse(input);
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion
    }
}