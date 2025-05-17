using Microsoft.Extensions.Configuration;
using SportifyX.Application.Services.Common.Interface;
using System.Text;
using System.Text.Json;

namespace SportifyX.Application.Services.Common
{
    public class SmsSenderService(IConfiguration configuration) : ISmsSenderService
    {
        private readonly HttpClient _httpClient = new HttpClient();
        private readonly string? _fast2SmsApiKey = configuration["SmsSettings:Fast2SmsApiKey"];

        public async Task<bool> SendSmsAsync(string mobileNumber, string message)
        {
            try
            {
                var payload = new
                {
                    route = "q",
                    message = message,
                    language = "english",
                    numbers = mobileNumber
                };

                var request = new HttpRequestMessage(HttpMethod.Post, "https://www.fast2sms.com/dev/bulkV2")
                {
                    Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
                };
                request.Headers.Add("authorization", _fast2SmsApiKey);

                var response = await _httpClient.SendAsync(request);
                return response.IsSuccessStatusCode;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string GenerateVerificationCode()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }
    }
}
