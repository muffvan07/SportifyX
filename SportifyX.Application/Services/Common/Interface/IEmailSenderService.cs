using SportifyX.Application.ResponseModels.Common;

namespace SportifyX.Application.Services.Common.Interface
{
    public interface IEmailSenderService
    {
        Task<bool> SendEmailAsync(EmailModel emailModel);
    }
}
