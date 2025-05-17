using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;

namespace SportifyX.Application.Services.Interface
{
    /// <summary>
    /// IAuthService
    /// </summary>
    public interface IAuthService
    {
        /// <summary>
        /// Registers the user asynchronous.
        /// </summary>
        /// <param name="userRegistrationDto">The user registration dto.</param>
        /// <returns></returns>
        Task<ApiResponse<RegisterUserResponseModel>> RegisterUserAsync(UserRegistrationDto userRegistrationDto);

        /// <summary>
        /// Logins the asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        Task<ApiResponse<LoginUserResponseModel>> LoginAsync(string email, string password);

        /// <summary>
        /// Logouts the asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> LogoutAsync(long userId, string token);

        /// <summary>
        /// Initiates the email verification asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> InitiateEmailVerificationAsync(long userId);

        /// <summary>
        /// Confirms the email verification asynchronous.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> ConfirmEmailVerificationAsync(string token);

        /// <summary>
        /// Sends the mobile verification code asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="countryCode">The country code.</param>
        /// <param name="mobileNumber">The mobile number.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> SendMobileVerificationCodeAsync(long userId, string countryCode, string mobileNumber);

        /// <summary>
        /// Confirms the mobile verification code asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="countryCode">The country code.</param>
        /// <param name="mobileNumber">The mobile number.</param>
        /// <param name="verificationCode">The verification code.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> ConfirmMobileVerificationCodeAsync(long userId, string countryCode, string mobileNumber, string verificationCode);
    }
}
