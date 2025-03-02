using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Helpers;

namespace SportifyX.API.Controllers
{
    /// <summary>
    /// UserController
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Mvc.ControllerBase" />
    [ApiController]
    [Route("api/user")]
    public class UserController(IUserService authService, IExceptionHandlingService exceptionHandlingService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The user service
        /// </summary>
        private readonly IUserService _userService = authService;

        /// <summary>
        /// The exception handling service
        /// </summary>
        private readonly IExceptionHandlingService _exceptionHandlingService = exceptionHandlingService;

        #endregion

        #region Methods

        #region Register User

        /// <summary>
        /// Registers the specified registration dto.
        /// </summary>
        /// <param name="registrationDto">The registration dto.</param>
        /// <returns></returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto registrationDto)
        {
            try
            {
                // Call the service to register the user
                var response = await _userService.RegisterUserAsync(registrationDto);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    // Return success response with detailed information from service
                    return Ok(response);
                }

                // Return the appropriate failure response with status code and error details
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region User Login

        /// <summary>
        /// Logins the specified login dto.
        /// </summary>
        /// <param name="loginDto">The login dto.</param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDto loginDto)
        {
            try
            {
                var response = await _userService.LoginAsync(loginDto.Email, loginDto.Password);

                // Return based on response status
                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region User Logout

        /// <summary>
        /// Logouts the specified dto.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutDto dto)
        {
            try
            {
                var response = await _userService.LogoutAsync(dto.UserId, dto.Token);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Unlock User

        /// <summary>
        /// Unlocks the user.
        /// </summary>
        /// <param name="unlockUserDto">The unlock user dto.</param>
        /// <returns></returns>
        [HttpPost("unlock")]
        public async Task<IActionResult> UnlockUser([FromBody] UnlockUserDto unlockUserDto)
        {
            try
            {
                var response = await _userService.UnlockUserAsync(unlockUserDto.Email, unlockUserDto.AdminUserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Get Logged in Users

        /// <summary>
        /// Gets the logged in users.
        /// </summary>
        /// <returns></returns>
        [HttpGet("active-sessions")]
        public async Task<IActionResult> GetLoggedInUsers(long adminUserId)
        {
            try
            {
                var response = await _userService.GetLoggedInUsersAsync(adminUserId);

                // Return based on response status
                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Add User Role

        /// <summary>
        /// Adds the user role.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("roles/add")]
        public async Task<IActionResult> AddUserRole([FromBody] AddRoleDto dto)
        {
            try
            {
                var response = await _userService.AddRoleToUserAsync(dto.UserId, dto.RoleId, dto.CurrentUserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Remove User Role

        /// <summary>
        /// Removes the user role.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("roles/remove")]
        public async Task<IActionResult> RemoveUserRole([FromBody] RemoveRoleDto dto)
        {
            try
            {
                var response = await _userService.RemoveRoleFromUserAsync(dto.UserId, dto.RoleId, dto.CurrentUserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Get User Roles

        /// <summary>
        /// Gets the user roles.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        [HttpGet("roles")]
        public async Task<IActionResult> GetUserRoles(long userId)
        {
            try
            {
                var response = await _userService.GetUserRolesAsync(userId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Request Password Reset Token

        /// <summary>
        /// Requests the password reset.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("password/request-recovery")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordRecoveryRequestDto dto)
        {
            try
            {
                var response = await _userService.GeneratePasswordResetTokenAsync(dto.Email);

                // Send token via email (or other means)

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Reset User Passoword

        /// <summary>
        /// Resets the password.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("password/reset")]
        public async Task<IActionResult> ResetPassword([FromBody] PasswordResetDto dto)
        {
            try
            {
                var response = await _userService.ResetPasswordAsync(dto.Email, dto.Token, dto.NewPassword);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Change User Password

        /// <summary>
        /// Changes the password.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("password/change")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            try
            {
                var response = await _userService.ChangePasswordAsync(dto.Email, dto.CurrentPassword, dto.NewPassword);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Initiate Email Verification

        /// <summary>
        /// Initiates the email verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-email/initiate")]
        public async Task<IActionResult> InitiateEmailVerification([FromBody] InitiateEmailVerificationDto request)
        {
            try
            {
                var response = await _userService.InitiateEmailVerificationAsync(request.UserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Confirm Email Verification

        /// <summary>
        /// Confirms the email verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-email/confirm")]
        public async Task<IActionResult> ConfirmEmailVerification([FromBody] ConfirmEmailVerificationDto request)
        {
            try
            {
                var response = await _userService.ConfirmEmailVerificationAsync(request.UserId, request.Email, request.Token);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Initiate Mobile Verification

        /// <summary>
        /// Initiates the mobile verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-mobile/initiate")]
        public async Task<IActionResult> InitiateMobileVerification([FromBody] InitiateMobileVerificationDto request)
        {
            try
            {
                var response = await _userService.SendMobileVerificationCodeAsync(request.UserId, request.CountryCode, request.MobileNumber);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Confirm Mobile Verification

        /// <summary>
        /// Confirms the mobile verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-mobile/confirm")]
        public async Task<IActionResult> ConfirmMobileVerification([FromBody] ConfirmMobileVerificationDto request)
        {
            try
            {
                var response = await _userService.ConfirmMobileVerificationCodeAsync(request.UserId, request.CountryCode, request.MobileNumber, request.VerificationCode);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Enable 2-Factor Authentication

        /// <summary>
        /// Enables the two factor authentication.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("enable-2fa")]
        public async Task<IActionResult> EnableTwoFactorAuthentication([FromBody] TwoFactorAuthDto dto)
        {
            try
            {
                var response = await _userService.EnableTwoFactorAsync(dto.UserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #endregion
    }
}
