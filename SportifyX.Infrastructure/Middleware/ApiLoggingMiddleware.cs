using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;
using System.Diagnostics;
using System.Text;

namespace SportifyX.Infrastructure.Middleware
{
    public class ApiLoggingMiddleware(RequestDelegate next, ILogger<ApiLoggingMiddleware> logger, IServiceScopeFactory scopeFactory)
    {
        #region Variables

        /// <summary>
        /// The next
        /// </summary>
        private readonly RequestDelegate _next = next;

        /// <summary>
        /// The logger
        /// </summary>
        private readonly ILogger<ApiLoggingMiddleware> _logger = logger;

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
            try
            {
                var stopwatch = Stopwatch.StartNew();
                var requestBody = await ReadRequestBodyAsync(context);
                var queryParams = context.Request.Query.Count > 0 ? SerializeJson(context.Request.Query) : null;
                var originalResponseBodyStream = context.Response.Body;
                var fullRequestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}"; // ✅ Capture full URL

                using var responseBodyStream = new MemoryStream();
                context.Response.Body = responseBodyStream; // Capture response

                await _next(context); // Proceed with the next middleware

                stopwatch.Stop();

                var responseBody = await ReadResponseBodyAsync(context);
                var statusCode = context.Response.StatusCode;
                var executionTime = stopwatch.ElapsedMilliseconds;

                var logEntry = new ApiLog
                {
                    RequestPath = fullRequestUrl,
                    HttpMethod = context.Request.Method,
                    RequestHeaders = SerializeJson(context.Request.Headers),
                    QueryParams = queryParams,
                    RequestBody = requestBody,
                    ResponseHeaders = SerializeJson(context.Response.Headers),
                    ResponseBody = responseBody,
                    StatusCode = statusCode,
                    ClientIp = context.Connection.RemoteIpAddress?.ToString(),
                    UserId = 0,
                    //UserId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value,
                    ExecutionTimeMs = executionTime,
                    CreationDate = DateTime.UtcNow
                };

                using var scope = _scopeFactory.CreateScope();
                var repository = scope.ServiceProvider.GetRequiredService<IGenericRepository<ApiLog>>();

                await repository.AddAsync(logEntry);

                responseBodyStream.Seek(0, SeekOrigin.Begin);
                await responseBodyStream.CopyToAsync(originalResponseBodyStream); // Copy response back to client
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save to database.");
            }
        }

        #endregion

        #region Private Methods

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
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                string body = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;
                return MinifyJson(body);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Reads the response body asynchronous.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        private static async Task<string> ReadResponseBodyAsync(HttpContext context)
        {
            try
            {
                context.Response.Body.Seek(0, SeekOrigin.Begin);
                using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);
                string body = await reader.ReadToEndAsync();
                context.Response.Body.Seek(0, SeekOrigin.Begin);
                return MinifyJson(body);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Minifies the json.
        /// </summary>
        /// <param name="json">The json.</param>
        /// <returns></returns>
        private static string MinifyJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            try
            {
                return JsonConvert.SerializeObject(JsonConvert.DeserializeObject(json), Formatting.None);
            }
            catch
            {
                return json; // Return original if not valid JSON
            }
        }

        /// <summary>
        /// Serializes the json.
        /// </summary>
        /// <param name="obj">The object.</param>
        /// <returns></returns>
        private static string SerializeJson(object obj)
        {
            return JsonConvert.SerializeObject(obj, Formatting.None);
        }

        #endregion
    }
}
