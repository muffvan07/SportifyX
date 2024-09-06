using SportifyX.Application.DTOs;

namespace SportifyX.Application.Interfaces
{
    public interface IAuthService
    {
        Task RegisterAsync(UserRegistrationDto userRegistrationDto);
        Task<string> LoginAsync(UserLoginDto userLoginDto);  // Return JWT token on success
        Task LogoutAsync();
        Task ResetPasswordAsync(PasswordResetDto passwordResetDto);
    }
}
