using SportifyX.Application.DTOs;
using SportifyX.Application.Interfaces;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IGenericRepository<User> _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IJwtTokenGenerator _jwtTokenGenerator;

        public AuthService(IGenericRepository<User> userRepository, IPasswordHasher passwordHasher, IJwtTokenGenerator jwtTokenGenerator)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _jwtTokenGenerator = jwtTokenGenerator;
        }

        public async Task RegisterAsync(UserRegistrationDto userRegistrationDto)
        {
            var hashedPassword = _passwordHasher.HashPassword(userRegistrationDto.Password);
            var newUser = new User
            {
                FirstName = userRegistrationDto.FirstName,
                LastName = userRegistrationDto.LastName,
                Email = userRegistrationDto.Email,
                PasswordHash = hashedPassword,
                Role = "Customer",  // Default role for new users
                CreatedAt = DateTime.UtcNow
            };
            await _userRepository.AddAsync(newUser);
        }

        public async Task<string> LoginAsync(UserLoginDto userLoginDto)
        {
            var user = await _userRepository.GetAsync(x => x.Email == userLoginDto.Email);
            if (user == null || !_passwordHasher.VerifyPassword(user.PasswordHash, userLoginDto.Password))
            {
                throw new UnauthorizedAccessException("Invalid credentials");
            }

            return _jwtTokenGenerator.GenerateToken(user);  // Return JWT token
        }

        public async Task LogoutAsync()
        {
            // Implement logout logic (e.g., token invalidation)
        }

        public async Task ResetPasswordAsync(PasswordResetDto passwordResetDto)
        {
            var user = await _userRepository.GetAsync(x => x.Email == passwordResetDto.Email);

            if (user == null)
            {
                throw new KeyNotFoundException("User not found");
            }

            user.PasswordHash = _passwordHasher.HashPassword(passwordResetDto.NewPassword);
            await _userRepository.UpdateAsync(user);
        }
    }
}
