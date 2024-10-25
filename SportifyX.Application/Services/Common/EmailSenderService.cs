using Microsoft.Extensions.Options;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Common.Interface;
using SportifyX.Domain.Settings;
using System.Net;
using System.Net.Mail;

namespace SportifyX.Application.Services.Common
{
    public class EmailSenderService : IEmailSenderService
    {
        private readonly EmailSettings _emailSettings;

        public EmailSenderService(IOptions<EmailSettings> emailSettings)
        {
            _emailSettings = emailSettings.Value;
        }

        public async Task<bool> SendEmailAsync(EmailModel emailModel)
        {
            try
            {
                using (var smtpClient = new SmtpClient(_emailSettings.SmtpServer, _emailSettings.Port))
                {
                    smtpClient.Credentials = new NetworkCredential(_emailSettings.Username, _emailSettings.Password);
                    smtpClient.EnableSsl = _emailSettings.UseSSL;

                    var mailMessage = new MailMessage
                    {
                        From = new MailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
                        Subject = emailModel.Subject,
                        Body = emailModel.Body,
                        IsBodyHtml = true
                    };

                    mailMessage.To.Add(emailModel.To);

                    await smtpClient.SendMailAsync(mailMessage);

                    return true;
                }
            }
            catch (Exception ex)
            {
                return false;
            }
        }
    }
}
