using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.DTOs;
using SportifyX.Application.Interfaces;

namespace SportifyX.API.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        private readonly IAuthService _authService = authService;

        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(object))]
        [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(object))]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto registrationDto)
        {
            try
            {
                var result = await _authService.RegisterAsync(registrationDto.Email, registrationDto.Username, registrationDto.Password, registrationDto.PhoneNumber, registrationDto.Role);

                if (result)
                {
                    return Ok(new { message = "Registration successful." });
                }

                return BadRequest(new { message = "Registration failed." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDto loginDto)
        {
            try
            {
                var token = await _authService.LoginAsync(loginDto.Email, loginDto.Password);

                return Ok(new { loginToken = token });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutDto dto)
        {
            try
            {
                var success = await _authService.LogoutAsync(dto.UserId, dto.Token);

                if (success)
                {
                    return Ok(new { message = "Successfully logged out" });
                }

                return BadRequest(new { message = "Logout failed" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("password-recovery")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordRecoveryRequestDto dto)
        {
            try
            {
                var token = await _authService.GeneratePasswordResetTokenAsync(dto.Email);

                // Send token via email (or other means)

                return Ok(new { resetToken = token });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] PasswordResetDto dto)
        {
            try
            {
                var success = await _authService.ResetPasswordAsync(dto.Email, dto.Token, dto.NewPassword);

                if (success)
                {
                    return Ok(new { message = "Password has been reset" });
                }

                return BadRequest(new { message = "Password reset failed." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            try
            {
                var success = await _authService.ChangePasswordAsync(dto.Email, dto.CurrentPassword, dto.NewPassword);

                if (success)
                {
                    return Ok("Password changed successfully.");
                }

                return BadRequest("Failed to change password.");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody] AddRoleDto dto)
        {
            try
            {
                var success = await _authService.AddRoleToUserAsync(dto.UserId, dto.RoleName);
                return success ? Ok("Role added.") : BadRequest("Failed to add role.");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("remove-role")]
        public async Task<IActionResult> RemoveRole([FromBody] RemoveRoleDto dto)
        {
            try
            {
                var success = await _authService.RemoveRoleFromUserAsync(dto.UserId, dto.RoleName);
                return success ? Ok("Role removed.") : BadRequest("Failed to remove role.");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("roles/{userId}")]
        public async Task<IActionResult> GetUserRoles(Guid userId)
        {
            var roles = await _authService.GetUserRolesAsync(userId);
            return Ok(roles);
        }

        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailDto dto)
        {
            try
            {
                var success = await _authService.ConfirmEmailAsync(dto.UserId, dto.ConfirmationCode);
                return success ? Ok("Email confirmed.") : BadRequest("Invalid confirmation code.");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("confirm-phone")]
        public async Task<IActionResult> ConfirmPhoneNumber([FromBody] ConfirmPhoneDto dto)
        {
            try
            {
                var success = await _authService.ConfirmPhoneNumberAsync(dto.UserId, dto.ConfirmationCode);
                return success ? Ok("Phone number confirmed.") : BadRequest("Invalid confirmation code.");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("enable-2fa")]
        public async Task<IActionResult> EnableTwoFactorAuthentication([FromBody] TwoFactorAuthDto dto)
        {
            try
            {
                var success = await _authService.EnableTwoFactorAsync(dto.UserId);
                if (success)
                {
                    return Ok("Two-Factor Authentication enabled.");
                }

                return BadRequest("Failed to enable Two-Factor Authentication.");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
