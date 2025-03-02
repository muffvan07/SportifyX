using Microsoft.AspNetCore.Http;

namespace SportifyX.Application.Services.Interface
{
    public interface IExceptionHandlingService
    {
        Task LogExceptionAsync(Exception exception, HttpContext context);
    }
}
