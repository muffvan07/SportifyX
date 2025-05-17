namespace SportifyX.Application.Services.Common.Interface
{
    public interface ICommonService
    {
        Task<bool> SendEmail(Dictionary<string, string> to, Dictionary<string, string>? cc, Dictionary<string, string>? bcc, string subject, string body);
    }
}
