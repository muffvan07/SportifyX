using Microsoft.Extensions.Options;
using SportifyX.Application.Services.Common.Interface;
using SportifyX.Domain.Settings;

namespace SportifyX.Application.Services.Common
{
    /// <summary>
    /// CommonService
    /// </summary>
    /// <seealso cref="SportifyX.Application.Services.Common.Interface.ICommonService" />
    public class CommonService(
        IBrevoEmailService emailSenderService,
        IOptions<EmailSettingsApi> options) : ICommonService
    {
        #region Variables

        /// <summary>
        /// The email sender service
        /// </summary>
        private readonly IBrevoEmailService _emailSenderService = emailSenderService;

        /// <summary>
        /// The settings
        /// </summary>
        private readonly EmailSettingsApi _emailSettingsApi = options.Value;

        #endregion

        #region Public Methods

        #region Send Email

        /// <summary>
        /// Sends the email.
        /// </summary>
        /// <param name="to">To.</param>
        /// <param name="cc">The cc.</param>
        /// <param name="bcc">The BCC.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="body">The body.</param>
        /// <returns></returns>
        public async Task<bool> SendEmail(Dictionary<string, string> to, Dictionary<string, string>? cc, Dictionary<string, string>? bcc, string subject, string body)
        {
            var senderEmailsAndNames = new Dictionary<string, string>
            {
                { _emailSettingsApi.FromName, _emailSettingsApi.FromEmail }
            };

            try
            {
                var response = await _emailSenderService.SendEmailAsync(senderEmailsAndNames, to, cc, bcc, subject, body);

                if (!response.IsSuccessStatusCode) return false;
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }

        #endregion

        #endregion
    }
}
