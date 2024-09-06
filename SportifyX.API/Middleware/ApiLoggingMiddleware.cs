using SportifyX.Domain.Entities;
using SportifyX.Infrastructure.Services;
using System.Diagnostics;

namespace SportifyX.API.Middleware
{
    public class ApiLoggingMiddleware(RequestDelegate next, LogQueue logQueue)
    {
        private readonly RequestDelegate _next = next;
        private readonly LogQueue _logQueue = logQueue;

        public async Task InvokeAsync(HttpContext context)
        {
            var stopwatch = Stopwatch.StartNew();

            var request = context.Request;
            var requestBody = await ReadRequestBodyAsync(request);
            var originalBodyStream = context.Response.Body;

            using (var responseBodyStream = new MemoryStream())
            {
                context.Response.Body = responseBodyStream;

                await _next(context);

                stopwatch.Stop();

                var responseBody = await ReadResponseBodyAsync(responseBodyStream);

                var apiLog = new ApiLog
                {
                    HttpMethod = request.Method,
                    Endpoint = request.Path,
                    RequestBody = requestBody,
                    ResponseBody = responseBody,
                    ResponseTime = stopwatch.ElapsedMilliseconds,
                    Timestamp = DateTime.UtcNow
                };

                _logQueue.Enqueue(apiLog);

                await responseBodyStream.CopyToAsync(originalBodyStream);
            }
        }

        private async Task<string> ReadRequestBodyAsync(HttpRequest request)
        {
            request.EnableBuffering();
            using (var reader = new StreamReader(request.Body, leaveOpen: true))
            {
                var body = await reader.ReadToEndAsync();
                request.Body.Position = 0;
                return body;
            }
        }

        private async Task<string> ReadResponseBodyAsync(MemoryStream responseBodyStream)
        {
            responseBodyStream.Seek(0, SeekOrigin.Begin);
            using (var reader = new StreamReader(responseBodyStream))
            {
                return await reader.ReadToEndAsync();
            }
        }
    }
}
