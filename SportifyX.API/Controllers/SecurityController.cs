using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Helpers;

namespace SportifyX.API.Controllers
{
    /// <summary>
    /// SecurityController
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Mvc.ControllerBase" />
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class SecurityController(
        ISecurityService securityService, 
        IExceptionHandlingService exceptionHandlingService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The user service
        /// </summary>
        private readonly ISecurityService _securityService = securityService;

        /// <summary>
        /// The exception handling service
        /// </summary>
        private readonly IExceptionHandlingService _exceptionHandlingService = exceptionHandlingService;

        #endregion

        #region Public Methods

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
                var response = await _securityService.ChangePasswordAsync(dto.Email, dto.CurrentPassword, dto.NewPassword);

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
                var response = await _securityService.GeneratePasswordResetTokenAsync(dto.Email);

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
                var response = await _securityService.ResetPasswordAsync(dto.Email, dto.Token, dto.NewPassword);

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
        /// Enables the two-factor authentication.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("enable-2fa")]
        public async Task<IActionResult> EnableTwoFactorAuthentication([FromBody] TwoFactorAuthDto dto)
        {
            try
            {
                var response = await _securityService.EnableTwoFactorAsync(dto.UserId);
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Disable 2-Factor Authentication

        /// <summary>
        /// Disables the two-factor authentication.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("disable-2fa")]
        public async Task<IActionResult> DisableTwoFactorAuthentication([FromBody] DisableTwoFactorDto dto)
        {
            try
            {
                var response = await _securityService.DisableTwoFactorAsync(dto.UserId, dto.Password);
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #endregion
    }
}
