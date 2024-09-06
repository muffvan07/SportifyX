using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.DTOs;
using SportifyX.Application.Interfaces;

namespace SportifyX.API.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegistrationDto registrationDto)
        {
            await _authService.RegisterAsync(registrationDto);
            return Ok("User registered successfully.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLoginDto loginDto)
        {
            var token = await _authService.LoginAsync(loginDto);
            return Ok(new { Token = token });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _authService.LogoutAsync();
            return Ok("Logged out successfully.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(PasswordResetDto resetDto)
        {
            await _authService.ResetPasswordAsync(resetDto);
            return Ok("Password reset successfully.");
        }
    }
}
