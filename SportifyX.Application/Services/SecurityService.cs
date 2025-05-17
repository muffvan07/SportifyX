using Microsoft.AspNetCore.Http;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;
using SportifyX.Application.Services.Common.Interface;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Helpers;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    /// <summary>
    /// SecurityService
    /// </summary>
    /// <seealso cref="SportifyX.Application.Services.Interface.ISecurityService" />
    public class SecurityService(
        IGenericRepository<User> userRepository,
        IGenericRepository<PasswordRecoveryToken> passwordRecoveryTokenRepository,
        IPasswordHasher passwordHasher,
        ICommonService commonService) : ISecurityService
    {
        #region Variables

        /// <summary>
        /// The user repository
        /// </summary>
        private readonly IGenericRepository<User> _userRepository = userRepository;

        /// <summary>
        /// The password recovery token repository
        /// </summary>
        private readonly IGenericRepository<PasswordRecoveryToken> _passwordRecoveryTokenRepository = passwordRecoveryTokenRepository;

        /// <summary>
        /// The password hasher
        /// </summary>
        private readonly IPasswordHasher _passwordHasher = passwordHasher;

        /// <summary>
        /// The common service
        /// </summary>
        private readonly ICommonService _commonService = commonService;

        #endregion

        #region Public Methods

        #region Change User Password

        /// <summary>
        /// Changes the password asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="currentPassword">The current password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ChangePasswordAsync(string email, string currentPassword, string newPassword)
        {
            var user = await _userRepository.GetAsync(x => x.Email == email);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Verify the current password
            if (!_passwordHasher.VerifyPassword(user.PasswordHash, currentPassword))
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("CurrentPasswordErrorMessage"));
            }

            // Check if the new password is different from the current password
            if (_passwordHasher.VerifyPassword(user.PasswordHash, newPassword))
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("SamePasswordErrorMessage"));
            }

            // Update password and security stamp
            user.PasswordHash = _passwordHasher.HashPassword(newPassword);
            user.SecurityStamp = Guid.NewGuid().ToString();  // Update security stamp
            user.ModificationDate = DateTime.UtcNow;
            user.ModifiedBy = user.Username;

            await _userRepository.UpdateAsync(user);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Generate Password Reset Token

        /// <summary>
        /// Generates the password reset token asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <returns></returns>
        public async Task<ApiResponse<PasswordResetTokenResponseModel>> GeneratePasswordResetTokenAsync(string email)
        {
            var user = await _userRepository.GetAsync(x => x.Email == email);

            if (user == null)
            {
                return ApiResponse<PasswordResetTokenResponseModel>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            var token = Guid.NewGuid().ToString();
            var expirationTime = DateTime.UtcNow.AddMinutes(1); // Token is valid for 1 minute

            var passwordRecoveryToken = new PasswordRecoveryToken
            {
                UserId = user.Id,
                Token = token,
                Expiration = expirationTime, // Set expiration time
                CreationDate = DateTime.UtcNow,
                CreatedBy = user.Username
            };

            await _passwordRecoveryTokenRepository.AddAsync(passwordRecoveryToken);

            var toEmailAndName = new Dictionary<string, string> { { user.FirstName, user.Email } };
            const string subject = "Password Reset Request";
            var body = $"<p>Hi {user.Username},</p>" +
                       $"<p>You requested a password reset. Click the link below to reset your password:</p>" +
                       $"<p><a href='https://your-app-url.com/reset-password?token={token}'>Reset Password</a></p>" +
                       "<p>If you did not request this, please ignore this email.</p>";

            // Send the email
            var emailSent = await _commonService.SendEmail(toEmailAndName, null, null, subject, body);

            if (!emailSent)
            {
                return ApiResponse<PasswordResetTokenResponseModel>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
            }

            var responseModel = new PasswordResetTokenResponseModel
            {
                Token = token,
                Expiration = expirationTime // Include expiration time in response
            };

            return ApiResponse<PasswordResetTokenResponseModel>.Success(responseModel);
        }

        #endregion

        #region Reset Password

        /// <summary>
        /// Resets the password asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="token">The token.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ResetPasswordAsync(string email, string token, string newPassword)
        {
            var user = await _userRepository.GetAsync(x => x.Email == email);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            var validTokens = await _passwordRecoveryTokenRepository.GetAllAsync(x => x.UserId == user.Id && x.Token == token && !x.IsUsed);

            var tokenModel = validTokens.OrderByDescending(t => t.Expiration).FirstOrDefault();

            if (tokenModel == null || tokenModel.Expiration < DateTime.UtcNow)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("InvalidOrExpiredTokenErrorMessage"));
            }

            user.PasswordHash = _passwordHasher.HashPassword(newPassword);
            user.SecurityStamp = Guid.NewGuid().ToString(); // Update security stamp
            user.ModificationDate = DateTime.UtcNow;
            user.ModifiedBy = user.Username;

            await _userRepository.UpdateAsync(user);

            tokenModel.IsUsed = true; // Mark token as used
            await _passwordRecoveryTokenRepository.UpdateAsync(tokenModel);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Enable 2-Factor Authentication

        /// <summary>
        /// Enables the two factor asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> EnableTwoFactorAsync(long userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            user.TwoFactorEnabled = true;
            user.ModificationDate = DateTime.UtcNow;
            user.ModifiedBy = user.Username;

            await _userRepository.UpdateAsync(user);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Disable 2-Factor Authentication

        /// <summary>
        /// Disables the two-factor authentication.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> DisableTwoFactorAsync(long userId, string password)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Example: Validate password (replace with your actual password check)
            var isPasswordValid = _passwordHasher.VerifyPassword(user.PasswordHash, password);

            if (!isPasswordValid)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status400BadRequest, ErrorMessageHelper.GetErrorMessage("InvalidCredentialsErrorMessage"));
            }

            user.TwoFactorEnabled = false;
            user.ModificationDate = DateTime.UtcNow;
            user.ModifiedBy = user.Username;

            await _userRepository.UpdateAsync(user);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #endregion
    }
}
