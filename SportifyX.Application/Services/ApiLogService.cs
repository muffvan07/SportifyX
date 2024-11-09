using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    public class ApiLogService(IGenericRepository<ApiLog> apiLogRepository) : IApiLogService
    {
        private readonly IGenericRepository<ApiLog> _apiLogRepository = apiLogRepository;

        public async Task LogAsync(ApiLog log)
        {
            await _apiLogRepository.AddAsync(log);
        }
    }
}
