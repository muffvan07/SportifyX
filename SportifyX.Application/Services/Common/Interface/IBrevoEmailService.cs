namespace SportifyX.Application.Services.Common.Interface
{
    public interface IBrevoEmailService
    {
        Task<HttpResponseMessage> SendEmailAsync(
            Dictionary<string, string> senderEmailAndName,
            Dictionary<string, string> toEmailsAndNames, // Key-Value pairs for To
            Dictionary<string, string>? ccEmailsAndNames, // Key-Value pairs for CC
            Dictionary<string, string>? bccEmailsAndNames,// Key-Value pairs for BCC
            string subject, string htmlContent);
    }
}
