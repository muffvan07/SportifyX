using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Helpers;

namespace SportifyX.API.Controllers
{
    /// <summary>
    /// AuthController
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Mvc.ControllerBase" />
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController(
        IAuthService authService, 
        IExceptionHandlingService exceptionHandlingService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The auth service
        /// </summary>
        private readonly IAuthService _authService = authService;

        /// <summary>
        /// The exception handling service
        /// </summary>
        private readonly IExceptionHandlingService _exceptionHandlingService = exceptionHandlingService;

        #endregion

        #region  Methods

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
                var response = await _authService.RegisterUserAsync(registrationDto);

                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
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
                var response = await _authService.LoginAsync(loginDto.Email, loginDto.Password);

                // Return based on response status
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
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
                var response = await _authService.LogoutAsync(dto.UserId, dto.Token);

                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
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
                var response = await _authService.InitiateEmailVerificationAsync(request.UserId);

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
                var response = await _authService.ConfirmEmailVerificationAsync(request.UserId, request.Email, request.Token);

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
                var response = await _authService.SendMobileVerificationCodeAsync(request.UserId, request.CountryCode, request.MobileNumber);

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
                var response = await _authService.ConfirmMobileVerificationCodeAsync(request.UserId, request.CountryCode, request.MobileNumber, request.VerificationCode);

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
