using Newtonsoft.Json;
using SportifyX.Application.Services.Common.Interface;
using System.Net.Http.Json;
using static SportifyX.Application.DTOs.Common.BrevoSendEmailDto;

namespace SportifyX.Application.Services.Common
{
    public class BrevoEmailService : IBrevoEmailService
    {
        private readonly HttpClient _httpClient;

        public BrevoEmailService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<HttpResponseMessage> SendEmailAsync(
            Dictionary<string, string> senderEmailAndName,
            Dictionary<string, string> toEmailsAndNames, // Key-Value pairs for To
            Dictionary<string, string>? ccEmailsAndNames, // Key-Value pairs for CC
            Dictionary<string, string>? bccEmailsAndNames, // Key-Value pairs for BCC
            string subject, string htmlContent)
        {
            string apiUrl = "https://api.brevo.com/v3/smtp/email";
            string apiKey = "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";

            var payload = new EmailPayload
            {
                Sender = ParseEmailsWithNames(senderEmailAndName).FirstOrDefault(),
                To = ParseEmailsWithNames(toEmailsAndNames),
                Cc = ParseEmailsWithNames(ccEmailsAndNames),
                Bcc = ParseEmailsWithNames(bccEmailsAndNames),
                Subject = subject,
                HtmlContent = htmlContent
            };

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("api-key", apiKey);
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");

            var jsonPayload = JsonConvert.SerializeObject(payload);

            return await _httpClient.PostAsJsonAsync(apiUrl, payload);
        }

        private static List<UserInfo> ParseEmailsWithNames(Dictionary<string, string>? emailNameDict)
        {
            if (emailNameDict == null || emailNameDict.Count == 0)
                return null;

            return emailNameDict.Select(e => new UserInfo
            {
                Name = e.Key,  // Set Name to the value of the dictionary
                Email = e.Value    // Set Email to the key of the dictionary
            }).ToList();
        }
    }
}
