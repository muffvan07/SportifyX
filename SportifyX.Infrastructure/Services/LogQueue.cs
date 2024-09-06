using Microsoft.Extensions.DependencyInjection;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;
using System.Collections.Concurrent;

namespace SportifyX.Infrastructure.Services
{
    public class LogQueue(IServiceProvider serviceProvider)
    {
        private readonly IServiceProvider _serviceProvider = serviceProvider;
        private readonly ConcurrentQueue<ApiLog> _logQueue = new ConcurrentQueue<ApiLog>();
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        private bool _isProcessing = false;

        public void Enqueue(ApiLog log)
        {
            _logQueue.Enqueue(log);
            ProcessQueueAsync(); // Trigger background processing
        }

        private async Task ProcessQueueAsync()
        {
            if (_isProcessing) return;

            _isProcessing = true;

            await _semaphore.WaitAsync();
            try
            {
                while (_logQueue.TryDequeue(out var log))
                {
                    await SaveLogAsync(log); // Process the log entry
                }
            }
            finally
            {
                _isProcessing = false;
                _semaphore.Release();
            }
        }

        private async Task SaveLogAsync(ApiLog log)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var apiLogRepository = scope.ServiceProvider.GetRequiredService<IGenericRepository<ApiLog>>();
                await apiLogRepository.AddAsync(log);
            }
        }
    }
}
