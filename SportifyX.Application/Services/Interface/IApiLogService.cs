using SportifyX.Domain.Entities;

namespace SportifyX.Application.Services.Interface
{
    public interface IApiLogService
    {
        Task LogAsync(ApiLog log);
    }
}
