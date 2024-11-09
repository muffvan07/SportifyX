using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.DTOs.User;
using SportifyX.Application.Services.Interface;

namespace SportifyX.API.Controllers
{
    [ApiController]
    [Route("api/user")]
    public class UserController(IUserService authService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The user service
        /// </summary>
        private readonly IUserService _userService = authService;

        #endregion

        #region Methods

        /// <summary>
        /// Registers the specified registration dto.
        /// </summary>
        /// <param name="registrationDto">The registration dto.</param>
        /// <returns></returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto registrationDto)
        {
            // Call the service to register the user
            var response = await _userService.RegisterUserAsync(registrationDto.Email, registrationDto.Username, registrationDto.Password, registrationDto.PhoneNumber, registrationDto.Role);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                // Return success response with detailed information from service
                return Ok(response);
            }

            // Return the appropriate failure response with status code and error details
            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Logins the specified login dto.
        /// </summary>
        /// <param name="loginDto">The login dto.</param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDto loginDto)
        {
            var response = await _userService.LoginAsync(loginDto.Email, loginDto.Password);

            // Return based on response status
            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Logouts the specified dto.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutDto dto)
        {
            var response = await _userService.LogoutAsync(dto.UserId, dto.Token);

            // Return based on response status
            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Gets the logged in users.
        /// </summary>
        /// <returns></returns>
        [HttpGet("active-sessions")]
        public async Task<IActionResult> GetLoggedInUsers()
        {
            var loggedInUsers = await _userService.GetLoggedInUsersAsync();

            if (loggedInUsers == null || !loggedInUsers.Any())
            {
                return NotFound(new { message = "No users are currently logged in." });
            }

            return Ok(loggedInUsers);
        }

        /// <summary>
        /// Requests the password reset.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("password/request-recovery")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordRecoveryRequestDto dto)
        {
            var response = await _userService.GeneratePasswordResetTokenAsync(dto.Email);

            // Send token via email (or other means)

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Resets the password.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("password/reset")]
        public async Task<IActionResult> ResetPassword([FromBody] PasswordResetDto dto)
        {
            var response = await _userService.ResetPasswordAsync(dto.Email, dto.Token, dto.NewPassword);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Changes the password.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("password/change")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            var response = await _userService.ChangePasswordAsync(dto.Email, dto.CurrentPassword, dto.NewPassword);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Gets the user roles.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        [HttpGet("roles")]
        public async Task<IActionResult> GetUserRoles(Guid userId)
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
                return BadRequest(ex.Message);
            }

        }

        /// <summary>
        /// Adds the user role.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("roles/add")]
        public async Task<IActionResult> AddUserRole([FromBody] AddRoleDto dto)
        {
            var response = await _userService.AddRoleToUserAsync(dto.UserId, dto.RoleName, dto.CurrentUserId);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Removes the user role.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("roles/remove")]
        public async Task<IActionResult> RemoveUserRole([FromBody] RemoveRoleDto dto)
        {
            var response = await _userService.RemoveRoleFromUserAsync(dto.UserId, dto.RoleName, dto.CurrentUserId);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Initiates the email verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-email/initiate")]
        public async Task<IActionResult> InitiateEmailVerification([FromBody] InitiateEmailVerificationDto request)
        {
            var response = await _userService.InitiateEmailVerificationAsync(request.UserId, request.Email);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Confirms the email verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-email/confirm")]
        public async Task<IActionResult> ConfirmEmailVerification([FromBody] ConfirmEmailVerificationDto request)
        {
            var response = await _userService.ConfirmEmailVerificationAsync(request.UserId, request.Email, request.Token);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Initiates the mobile verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-mobile/initiate")]
        public async Task<IActionResult> InitiateMobileVerification([FromBody] InitiateMobileVerificationDto request)
        {
            var response = await _userService.SendMobileVerificationCodeAsync(request.UserId, request.CountryCode, request.MobileNumber);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Confirms the mobile verification.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpPost("verify-mobile/confirm")]
        public async Task<IActionResult> ConfirmMobileVerification([FromBody] ConfirmMobileVerificationDto request)
        {
            var response = await _userService.ConfirmMobileVerificationCodeAsync(request.UserId, request.CountryCode, request.MobileNumber, request.VerificationCode);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Enables the two factor authentication.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("enable-2fa")]
        public async Task<IActionResult> EnableTwoFactorAuthentication([FromBody] TwoFactorAuthDto dto)
        {
            var response = await _userService.EnableTwoFactorAsync(dto.UserId);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Unlocks the user.
        /// </summary>
        /// <param name="unlockUserDto">The unlock user dto.</param>
        /// <returns></returns>
        [HttpPost("unlock")]
        public async Task<IActionResult> UnlockUser([FromBody] UnlockUserDto unlockUserDto)
        {
            var response = await _userService.UnlockUserAsync(unlockUserDto.Email, unlockUserDto.Password);

            if (response.StatusCode == StatusCodes.Status200OK)
            {
                return Ok(response);
            }

            return StatusCode(response.StatusCode, response);
        }

        #endregion
    }
}
