using SportifyX.Application.DTOs;

namespace SportifyX.Application.Interfaces
{
    public interface IAuthService
    {
        Task<bool> RegisterAsync(string email, string username, string password, string phoneNumber, string role);
        Task<string> LoginAsync(string email, string password);  // Return JWT token on success
        Task<bool> LogoutAsync(Guid userId, string token);
        Task<string> GeneratePasswordResetTokenAsync(string email);
        Task<bool> ResetPasswordAsync(string email, string token, string newPassword);
        Task<bool> ChangePasswordAsync(string email, string currentPassword, string newPassword);
        Task<bool> AddRoleToUserAsync(Guid userId, string roleName);
        Task<bool> RemoveRoleFromUserAsync(Guid userId, string roleName);
        Task<List<string>> GetUserRolesAsync(Guid userId);
        Task<bool> ConfirmEmailAsync(Guid userId, string confirmationCode);
        Task<bool> ConfirmPhoneNumberAsync(Guid userId, string verificationCode);
        Task<bool> EnableTwoFactorAsync(Guid userId);
    }
}
