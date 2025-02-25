using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;
using SportifyX.Domain.Entities;

namespace SportifyX.Application.Services.Interface
{
    public interface IUserService
    {
        Task<ApiResponse<RegisterUserResponseModel>> RegisterUserAsync(UserRegistrationDto userRegistrationDto);
        Task<ApiResponse<LoginUserResponseModel>> LoginAsync(string email, string password);  // Return JWT token on success
        Task<ApiResponse<bool>> LogoutAsync(long userId, string token);
        Task<ApiResponse<PasswordResetTokenResponseModel>> GeneratePasswordResetTokenAsync(string email);
        Task<ApiResponse<bool>> ResetPasswordAsync(string email, string token, string newPassword);
        Task<ApiResponse<bool>> ChangePasswordAsync(string email, string currentPassword, string newPassword);
        Task<ApiResponse<AddRoleResponseModel>> AddRoleToUserAsync(long userId, long roleId, long currentUserId);
        Task<ApiResponse<bool>> RemoveRoleFromUserAsync(long userId, long roleId, long currentUserId);
        Task<ApiResponse<UserRoleResponseModel>> GetUserRolesAsync(long userId);
        Task<ApiResponse<bool>> InitiateEmailVerificationAsync(long userId);
        Task<ApiResponse<bool>> ConfirmEmailVerificationAsync(long userId, string email, string token);
        Task<ApiResponse<bool>> SendMobileVerificationCodeAsync(long userId, string countryCode, string mobileNumber);
        Task<ApiResponse<bool>> ConfirmMobileVerificationCodeAsync(long userId, string countryCode, string mobileNumber, string verificationCode);
        Task<ApiResponse<bool>> EnableTwoFactorAsync(long userId);
        Task<ApiResponse<List<LoggedInUsersResponseModel>>> GetLoggedInUsersAsync(long adminUserId);
        Task<ApiResponse<bool>> UnlockUserAsync(string email, long adminUserId);
    }
}
