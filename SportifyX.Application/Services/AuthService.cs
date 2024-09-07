using Microsoft.EntityFrameworkCore;
using SportifyX.Application.DTOs;
using SportifyX.Application.Interfaces;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;
using System.Runtime.ConstrainedExecution;

namespace SportifyX.Application.Services
{
    public class AuthService(
        IGenericRepository<User> userRepository,
        IGenericRepository<UserSession> userSessionRepository,
        IGenericRepository<Role> roleRepository,
        IGenericRepository<UserRole> userRoleRepository,
        IGenericRepository<PasswordRecoveryToken> passwordRecoveryTokenRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenGenerator jwtTokenGenerator) : IAuthService
    {
        private readonly IGenericRepository<User> _userRepository = userRepository;
        private readonly IGenericRepository<UserSession> _userSessionRepository = userSessionRepository;
        private readonly IGenericRepository<Role> _roleRepository = roleRepository;
        private readonly IGenericRepository<UserRole> _userRoleRepository = userRoleRepository;
        private readonly IGenericRepository<PasswordRecoveryToken> _passwordRecoveryTokenRepository = passwordRecoveryTokenRepository;
        private readonly IPasswordHasher _passwordHasher = passwordHasher;
        private readonly IJwtTokenGenerator _jwtTokenGenerator = jwtTokenGenerator;

        public async Task<bool> RegisterAsync(string email, string username, string password, string phoneNumber, string role)
        {
            var existingUser = await _userRepository.GetAsync(x => x.Email == email);

            if (existingUser != null)
            {
                throw new Exception("User with this email already exists.");
            }

            var passwordHash = _passwordHasher.HashPassword(password);

            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = username,
                Email = email,
                PasswordHash = _passwordHasher.HashPassword(password),  // Password hashing
                SecurityStamp = Guid.NewGuid().ToString(),              // Unique identifier for security
                PhoneNumber = phoneNumber,
                IsPhoneNumberConfirmed = false,                        // Confirmation through verification process
                IsEmailConfirmed = false,                              // Confirmation through email verification
                LockoutEnabled = false,                                // Disabled initially
                AccessFailedCount = 0,                                 // No failed attempts yet
                TwoFactorEnabled = false,                              // Can be enabled later
                CreatedDate = DateTime.Now,
                LastModifiedDate = null
            };

            await _userRepository.AddAsync(user);

            var userRole = await _roleRepository.GetAsync(x => x.Name == role);

            if (userRole != null)
            {
                await _userRoleRepository.AddAsync(new UserRole
                {
                    UserId = user.Id,
                    RoleId = userRole.Id
                });
            }

            return true;
        }

        public async Task<UserSession> GetValidSessionAsync(Guid userId, string token)
        {
            return await _userSessionRepository.GetAsync(us => us.UserId == userId && us.Token == token && us.IsValid && us.Expiration > DateTime.Now);
        }

        public async Task InvalidateSessionAsync(Guid sessionId)
        {
            var session = await _userSessionRepository.GetByIdAsync(sessionId);

            if (session != null)
            {
                session.IsValid = false;

                await _userSessionRepository.UpdateAsync(session);
            }
        }

        public async Task<string> LoginAsync(string email, string password)
        {
            var user = await _userRepository.GetAsync(x => x.Email == email);

            if (user == null)
            {
                throw new Exception("Invalid credentials.");
            }

            // Check if the user is locked out
            if (user.LockoutEnabled && user.LockoutEndDateUtc > DateTime.Now)
            {
                throw new Exception("User is currently locked out. Please try again later.");
            }

            if (!_passwordHasher.VerifyPassword(user.PasswordHash, password))
            {
                // Handle failed login attempt
                var isLockedOut = await HandleFailedLoginAsync(user.Id);

                if (isLockedOut)
                {
                    throw new Exception("Account locked due to multiple failed login attempts. Try again later.");
                }

                throw new Exception("Invalid credentials.");
            }

            // Reset access failed count if login is successful
            await ResetAccessFailedCountAsync(user.Id);

            // Generate JWT token
            var token = _jwtTokenGenerator.GenerateToken(user);

            // Create a new session for the user
            var userSession = new UserSession
            {
                UserId = user.Id,
                Token = token,
                Expiration = DateTime.Now.AddHours(2), // Example expiration time
                IsValid = true
            };

            await _userSessionRepository.AddAsync(userSession);

            return token;
        }

        public async Task<bool> LogoutAsync(Guid userId, string token)
        {
            var session = await GetValidSessionAsync(userId, token);

            if (session == null)
            {
                throw new Exception("Invalid session.");
            }

            await InvalidateSessionAsync(session.Id);

            return true;
        }

        public async Task<string> GeneratePasswordResetTokenAsync(string email)
        {
            var user = await _userRepository.GetAsync(x => x.Email == email);
            if (user == null)
            {
                throw new Exception("User with this email does not exist.");
            }

            var token = Guid.NewGuid().ToString();
            var passwordRecoveryToken = new PasswordRecoveryToken
            {
                UserId = user.Id,
                Token = token,
                Expiration = DateTime.Now.AddHours(1) // Token is valid for 1 hour
            };

            await _passwordRecoveryTokenRepository.AddAsync(passwordRecoveryToken);

            // Send token via email or other means (omitted for brevity)
            return token;
        }

        public async Task<bool> ResetPasswordAsync(string email, string token, string newPassword)
        {
            var user = await _userRepository.GetAsync(x => x.Email == email);

            if (user == null)
            {
                throw new Exception("User with this email does not exist.");
            }

            var validToken = await _passwordRecoveryTokenRepository.GetAllAsync(x => x.UserId == user.Id && x.Token == token && !x.IsUsed);

            var tokenModel = validToken.OrderByDescending(t => t.Expiration).ToList().FirstOrDefault();

            if (tokenModel == null || tokenModel.Expiration < DateTime.Now)
            {
                throw new Exception("Invalid or expired password reset token.");
            }

            user.PasswordHash = _passwordHasher.HashPassword(newPassword);
            user.SecurityStamp = Guid.NewGuid().ToString();  // Update security stamp
            user.LastModifiedDate = DateTime.Now;

            await _userRepository.UpdateAsync(user);

            tokenModel.IsUsed = true; // Mark token as used

            await _passwordRecoveryTokenRepository.UpdateAsync(tokenModel);

            return true;
        }

        public async Task<bool> ChangePasswordAsync(string email, string currentPassword, string newPassword)
        {
            var user = await _userRepository.GetAsync(x => x.Email == email);

            if (user == null)
            {
                throw new Exception("User with this email does not exist.");
            }

            if (!_passwordHasher.VerifyPassword(user.PasswordHash, currentPassword))
            {
                throw new Exception("Current password is incorrect.");
            }

            user.PasswordHash = _passwordHasher.HashPassword(newPassword);
            user.SecurityStamp = Guid.NewGuid().ToString();  // Update security stamp
            user.LastModifiedDate = DateTime.Now;

            await _userRepository.UpdateAsync(user);

            return true;
        }

        public async Task<bool> AddRoleToUserAsync(Guid userId, string roleName)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                throw new Exception("User not found.");
            }

            var role = await _roleRepository.GetAsync(x => x.Name == roleName);

            if (role == null)
            {
                throw new Exception("Role not found.");
            }

            var userRole = new UserRole
            {
                UserId = user.Id,
                RoleId = role.Id
            };

            await _userRoleRepository.AddAsync(userRole);

            return true;
        }

        public async Task<bool> RemoveRoleFromUserAsync(Guid userId, string roleName)
        {
            var user = await _userRepository.GetByIdAsync(userId) ?? throw new Exception("User not found.");

            var role = await _roleRepository.GetAsync(x => x.Name == roleName) ?? throw new Exception("Role not found.");

            var userRole = await _userRoleRepository.GetAsync(ur => ur.UserId == userId && ur.RoleId == role.Id);

            if (userRole != null)
            {
                await _userRoleRepository.DeleteAsync(userRole.UserId);
            }

            return true;
        }

        public async Task<List<string>> GetUserRolesAsync(Guid userId)
        {
            var userRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == userId);

            return userRoles.Select(ur => ur.Role.Name).ToList();
        }

        public async Task<bool> ConfirmEmailAsync(Guid userId, string confirmationCode)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null || user.SecurityStamp != confirmationCode)
            {
                throw new Exception("Invalid confirmation code.");
            }

            user.IsEmailConfirmed = true;
            user.LastModifiedDate = DateTime.Now;

            await _userRepository.UpdateAsync(user);
            return true;
        }

        public async Task<bool> ConfirmPhoneNumberAsync(Guid userId, string verificationCode)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null || user.SecurityStamp != verificationCode)
            {
                throw new Exception("Invalid verification code.");
            }

            user.IsPhoneNumberConfirmed = true;
            user.LastModifiedDate = DateTime.Now;

            await _userRepository.UpdateAsync(user);
            return true;
        }

        private async Task<bool> HandleFailedLoginAsync(Guid userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            user.AccessFailedCount += 1;
            if (user.AccessFailedCount >= 5)
            {
                user.LockoutEnabled = true;
                user.LockoutEndDateUtc = DateTime.Now.AddMinutes(15); // Lockout for 15 minutes
            }

            await _userRepository.UpdateAsync(user);
            return user.LockoutEnabled;
        }

        private async Task<bool> ResetAccessFailedCountAsync(Guid userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            user.AccessFailedCount = 0;
            user.LastModifiedDate = DateTime.Now;

            await _userRepository.UpdateAsync(user);
            return true;
        }

        public async Task<bool> EnableTwoFactorAsync(Guid userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            user.TwoFactorEnabled = true;
            user.LastModifiedDate = DateTime.Now;

            await _userRepository.UpdateAsync(user);
            return true;
        }
    }
}
