using SportifyX.Application.DTOs;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;
using SportifyX.Domain.Entities;

namespace SportifyX.Application.Interfaces
{
    public interface IUserService
    {
        Task<ApiResponse<RegisterUserResponseModel>> RegisterUserAsync(string email, string password, string username, string phoneNumber, string role);
        Task<ApiResponse<LoginUserResponseModel>> LoginAsync(string email, string password);  // Return JWT token on success
        Task<ApiResponse<bool>> LogoutAsync(Guid userId, string token);
        Task<ApiResponse<PasswordResetTokenResponseModel>> GeneratePasswordResetTokenAsync(string email);
        Task<ApiResponse<bool>> ResetPasswordAsync(string email, string token, string newPassword);
        Task<ApiResponse<bool>> ChangePasswordAsync(string email, string currentPassword, string newPassword);
        Task<ApiResponse<AddRoleResponseModel>> AddRoleToUserAsync(Guid userId, string roleName, Guid currentUserId);
        Task<ApiResponse<bool>> RemoveRoleFromUserAsync(Guid userId, string roleName, Guid currentUserId);
        Task<ApiResponse<UserRoleResponseModel>> GetUserRolesAsync(Guid userId);
        Task<ApiResponse<bool>> InitiateEmailVerificationAsync(Guid userId, string email);
        Task<ApiResponse<bool>> ConfirmEmailVerificationAsync(Guid userId, string email, Guid token);
        Task<ApiResponse<bool>> SendMobileVerificationCodeAsync(Guid userId, string countryCode, string mobileNumber);
        Task<ApiResponse<bool>> ConfirmMobileVerificationCodeAsync(Guid userId, string countryCode, string mobileNumber, string verificationCode);
        Task<ApiResponse<bool>> EnableTwoFactorAsync(Guid userId);
        Task<IEnumerable<User>> GetLoggedInUsersAsync();
        Task<ApiResponse<bool>> UnlockUserAsync(string email, string password);
    }
}
