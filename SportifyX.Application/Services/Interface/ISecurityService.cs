using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;

namespace SportifyX.Application.Services.Interface
{
    /// <summary>
    /// ISecurityService
    /// </summary>
    public interface ISecurityService
    {
        /// <summary>
        /// Changes the password asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="currentPassword">The current password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> ChangePasswordAsync(string email, string currentPassword, string newPassword);

        /// <summary>
        /// Generates the password reset token asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <returns></returns>
        Task<ApiResponse<PasswordResetTokenResponseModel>> GeneratePasswordResetTokenAsync(string email);

        /// <summary>
        /// Resets the password asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="token">The token.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> ResetPasswordAsync(string email, string token, string newPassword);

        /// <summary>
        /// Enables the two factor asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> EnableTwoFactorAsync(long userId);

        /// <summary>
        /// Disables the two factor asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> DisableTwoFactorAsync(long userId, string password);
    }
}
