using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;
using System.Diagnostics;
using System.Security.Claims;
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
            var correlationId = context.Request.Headers.TryGetValue("X-Correlation-ID", out var corrId)
                ? corrId.ToString()
                : Guid.NewGuid().ToString();

            context.Response.Headers["X-Correlation-ID"] = correlationId;

            var requestStartTime = DateTime.UtcNow;
            string? exceptionDetails = null;

            try
            {
                var stopwatch = Stopwatch.StartNew();
                var requestBody = await ReadRequestBodyAsync(context);
                var queryParams = context.Request.Query.Count > 0 ? SerializeJson(context.Request.Query) : null;
                var originalResponseBodyStream = context.Response.Body;
                var fullRequestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

                using var responseBodyStream = new MemoryStream();
                context.Response.Body = responseBodyStream;

                await _next(context);

                stopwatch.Stop();

                var responseBody = await ReadResponseBodyAsync(context);
                var statusCode = context.Response.StatusCode;
                var executionTime = stopwatch.ElapsedMilliseconds;

                // UserId extraction
                var userId = 0;

                var userIdClaim = context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (int.TryParse(userIdClaim, out var parsedUserId))
                    userId = parsedUserId;

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
                    UserId = userId,
                    ExecutionTimeMs = executionTime,
                    CreationDate = DateTime.UtcNow,
                    CorrelationId = correlationId,
                    RequestContentType = context.Request.ContentType,
                    RequestContentLength = context.Request.ContentLength,
                    ResponseContentType = context.Response.ContentType,
                    ResponseContentLength = context.Response.ContentLength,
                    UserAgent = context.Request.Headers["User-Agent"].ToString(),
                    Referer = context.Request.Headers["Referer"].ToString(),
                    Protocol = context.Request.Protocol,
                    RequestStartTime = requestStartTime,
                    RequestEndTime = DateTime.UtcNow,
                    Exception = exceptionDetails
                };

                using var scope = _scopeFactory.CreateScope();
                var repository = scope.ServiceProvider.GetRequiredService<IGenericRepository<ApiLog>>();

                await repository.AddAsync(logEntry);

                responseBodyStream.Seek(0, SeekOrigin.Begin);
                await responseBodyStream.CopyToAsync(originalResponseBodyStream);
            }
            catch (Exception ex)
            {
                exceptionDetails = ex.ToString();
                _logger.LogError(ex, "Failed to save to database.");

                // Optionally, log the failed request as well
                try
                {
                    var logEntry = new ApiLog
                    {
                        RequestPath = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}",
                        HttpMethod = context.Request.Method,
                        RequestHeaders = SerializeJson(context.Request.Headers),
                        QueryParams = context.Request.Query.Count > 0 ? SerializeJson(context.Request.Query) : null,
                        RequestBody = await ReadRequestBodyAsync(context),
                        ResponseHeaders = SerializeJson(context.Response.Headers),
                        ResponseBody = null,
                        StatusCode = context.Response.StatusCode,
                        ClientIp = context.Connection.RemoteIpAddress?.ToString(),
                        UserId = 0,
                        ExecutionTimeMs = 0,
                        CreationDate = DateTime.UtcNow,
                        CorrelationId = correlationId,
                        RequestContentType = context.Request.ContentType,
                        RequestContentLength = context.Request.ContentLength,
                        ResponseContentType = context.Response.ContentType,
                        ResponseContentLength = context.Response.ContentLength,
                        UserAgent = context.Request.Headers["User-Agent"].ToString(),
                        Referer = context.Request.Headers["Referer"].ToString(),
                        Protocol = context.Request.Protocol,
                        RequestStartTime = requestStartTime,
                        RequestEndTime = DateTime.UtcNow,
                        Exception = exceptionDetails
                    };

                    using var scope = _scopeFactory.CreateScope();
                    var repository = scope.ServiceProvider.GetRequiredService<IGenericRepository<ApiLog>>();
                    await repository.AddAsync(logEntry);
                }
                catch (Exception logEx)
                {
                    _logger.LogError(logEx, "Failed to log exception details to database.");
                }
            }
        }

        #endregion

        #region Private Methods

        private static async Task<string> ReadRequestBodyAsync(HttpContext context)
        {
            try
            {
                context.Request.EnableBuffering();
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                var body = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;
                return MinifyJson(body);
            }
            catch
            {
                return null;
            }
        }

        private static async Task<string> ReadResponseBodyAsync(HttpContext context)
        {
            try
            {
                context.Response.Body.Seek(0, SeekOrigin.Begin);
                using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);
                var body = await reader.ReadToEndAsync();
                context.Response.Body.Seek(0, SeekOrigin.Begin);
                return MinifyJson(body);
            }
            catch
            {
                return null;
            }
        }

        private static string MinifyJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            try
            {
                return JsonConvert.SerializeObject(JsonConvert.DeserializeObject(json), Formatting.None);
            }
            catch
            {
                return json;
            }
        }

        private static string SerializeJson(object obj)
        {
            return JsonConvert.SerializeObject(obj, Formatting.None);
        }

        #endregion
    }
}
