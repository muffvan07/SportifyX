using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Helpers;

namespace SportifyX.Infrastructure.Middleware
{
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
        /// Invokes the specified context.
        /// </summary>
        /// <param name="context">The context.</param>
        public async Task Invoke(HttpContext context)
        {
            string requestBody = await ReadRequestBodyAsync(context);

            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred.");

                using var scope = _scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<IExceptionHandlingService>();

                await service.LogExceptionAsync(ex, context);
                await HandleExceptionAsync(context);
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Handles the exception asynchronous.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        private static Task HandleExceptionAsync(HttpContext context)
        {
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;

            var response = ApiResponse<bool>.Fail(context.Response.StatusCode, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));

            return context.Response.WriteAsync(JsonConvert.SerializeObject(response));
        }

        /// <summary>
        /// Reads the request body asynchronous.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        private static async Task<string> ReadRequestBodyAsync(HttpContext context)
        {
            try
            {
                context.Request.EnableBuffering();
                using var reader = new StreamReader(context.Request.Body, System.Text.Encoding.UTF8, leaveOpen: true);
                string body = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;

                // Minify JSON if it's a valid JSON object
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
        /// Determines whether [is valid json] [the specified input].
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>
        ///   <c>true</c> if [is valid json] [the specified input]; otherwise, <c>false</c>.
        /// </returns>
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
