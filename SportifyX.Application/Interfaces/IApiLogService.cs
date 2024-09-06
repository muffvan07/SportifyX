using SportifyX.Domain.Entities;

namespace SportifyX.Application.Interfaces
{
    public interface IApiLogService
    {
        Task LogAsync(ApiLog log);
    }
}
