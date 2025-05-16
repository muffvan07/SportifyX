using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    public class ExceptionHandlingService(ILogger<ExceptionHandlingService> logger, IGenericRepository<ExceptionLog> exceptionLogRepository) : IExceptionHandlingService
    {
        /// <summary>
        /// The logger
        /// </summary>
        private readonly ILogger<ExceptionHandlingService> _logger = logger;

        /// <summary>
        /// The exception log repository
        /// </summary>
        private readonly IGenericRepository<ExceptionLog> _exceptionLogRepository = exceptionLogRepository;

        public async Task LogExceptionAsync(Exception exception, HttpContext context)
        {
            try
            {
                var requestBody = context.Items["RequestBody"] as string;

                var exceptionLog = new ExceptionLog
                {
                    ExceptionType = exception.GetType().Name,
                    Message = exception.Message,
                    StackTrace = exception.StackTrace,
                    Source = exception.Source,
                    TargetSite = exception.TargetSite?.ToString(),
                    RequestPath = context.Request.Path,
                    QueryString = context.Request.QueryString.ToString(),
                    RequestMethod = context.Request.Method,
                    RequestBody = requestBody,
                    UserId = 0,
                    //UserId = Convert.ToInt64(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value),
                    ClientIp = context.Connection.RemoteIpAddress?.ToString(),
                    MachineName = Environment.MachineName,
                    AppDomain = AppDomain.CurrentDomain.FriendlyName,
                    CreationDate = DateTime.UtcNow
                };

                await _exceptionLogRepository.AddAsync(exceptionLog);
            }
            catch (Exception dbEx)
            {
                _logger.LogError(dbEx, "Failed to log exception to database.");
            }
        }
    }
}
