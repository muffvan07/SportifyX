namespace SportifyX.Application.Services.Common.Interface
{
    public interface ISmsSenderService
    {
        Task<bool> SendSmsAsync(string mobileNumber, string message);
    }
}
