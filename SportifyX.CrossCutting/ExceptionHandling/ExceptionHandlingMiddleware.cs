using Microsoft.AspNetCore.Http;
using Serilog;

namespace SportifyX.CrossCutting.ExceptionHandling
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;

        public ExceptionHandlingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                Log.Error($"Something went wrong: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("An unexpected fault occurred.");
            }
        }
    }
}
