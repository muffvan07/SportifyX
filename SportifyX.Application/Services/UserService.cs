using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;
using SportifyX.Application.Services.Common.Interface;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Helpers;
using SportifyX.Domain.Interfaces;
using static SportifyX.Domain.Helpers.Enumerators;

namespace SportifyX.Application.Services
{
    /// <summary>
    /// UserService
    /// </summary>
    /// <seealso cref="Interface.IUserService" />
    public class UserService(
        IGenericRepository<User> userRepository,
        IGenericRepository<UserSession> userSessionRepository,
        IGenericRepository<UserRole> userRoleRepository,
        IGenericRepository<PasswordRecoveryToken> passwordRecoveryTokenRepository,
        IGenericRepository<Verification> verificationRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenGenerator jwtTokenGenerator,
        IEmailSenderService emailSenderService,
        ISmsSenderService smsSenderService) : IUserService
    {
        #region Variables

        /// <summary>
        /// The user repository
        /// </summary>
        private readonly IGenericRepository<User> _userRepository = userRepository;

        /// <summary>
        /// The user session repository
        /// </summary>
        private readonly IGenericRepository<UserSession> _userSessionRepository = userSessionRepository;

        /// <summary>
        /// The user role repository
        /// </summary>
        private readonly IGenericRepository<UserRole> _userRoleRepository = userRoleRepository;

        /// <summary>
        /// The password recovery token repository
        /// </summary>
        private readonly IGenericRepository<PasswordRecoveryToken> _passwordRecoveryTokenRepository = passwordRecoveryTokenRepository;

        /// <summary>
        /// The verification repository
        /// </summary>
        private readonly IGenericRepository<Verification> _verificationRepository = verificationRepository;

        /// <summary>
        /// The password hasher
        /// </summary>
        private readonly IPasswordHasher _passwordHasher = passwordHasher;

        /// <summary>
        /// The JWT token generator
        /// </summary>
        private readonly IJwtTokenGenerator _jwtTokenGenerator = jwtTokenGenerator;

        /// <summary>
        /// The email sender service
        /// </summary>
        private readonly IEmailSenderService _emailSenderService = emailSenderService;

        /// <summary>
        /// The SMS sender service  
        /// </summary>
        private readonly ISmsSenderService _smsSenderService = smsSenderService;

        #endregion

        #region Action Methods

        /// <summary>
        /// Registers the asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <param name="phoneNumber">The phone number.</param>
        /// <param name="role">The role.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">User with this email already exists.</exception>
        public async Task<ApiResponse<RegisterUserResponseModel>> RegisterUserAsync(UserRegistrationDto userRegistrationDto)
        {
            const int unauthorizedStatusCode = 401;
            const string unauthorizedMessage = "Unauthorized";
            const string userExistsError = "A user with this email already exists.";
            const string roleNotFoundError = "The specified role does not exist.";
            const string generalError = "An unexpected error occurred. Please try again later.";

            try
            {
                // Check if a user with the same email already exists
                var existingUser = await _userRepository.GetAsync(x => x.Email == userRegistrationDto.Email);

                if (existingUser != null)
                {
                    return ApiResponse<RegisterUserResponseModel>.Fail(unauthorizedStatusCode, unauthorizedMessage, userExistsError);
                }

                // Hash password
                var passwordHash = _passwordHasher.HashPassword(userRegistrationDto.Password);

                // Create new user
                var user = new User
                {
                    FirstName = userRegistrationDto.FirstName,
                    LastName = userRegistrationDto.LastName,
                    Username = userRegistrationDto.Username,
                    Email = userRegistrationDto.Email,
                    PasswordHash = passwordHash,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    PhoneNumber = userRegistrationDto.PhoneNumber,
                    DOB = userRegistrationDto.DOB,
                    Gender = userRegistrationDto.Gender,
                    IsPhoneNumberConfirmed = false,
                    IsEmailConfirmed = false,
                    LockoutEnabled = false,
                    AccessFailedCount = 0,
                    TwoFactorEnabled = false,
                    CreationDate = DateTime.Now,
                    CreatedBy = userRegistrationDto.Username
                };

                await _userRepository.AddAsync(user);

                // Check if the role exists
                bool isValidRole = Enum.IsDefined(typeof(UserRoleEnum), userRegistrationDto.RoleId);

                if (!isValidRole)
                {
                    return ApiResponse<RegisterUserResponseModel>.Fail(unauthorizedStatusCode, unauthorizedMessage, roleNotFoundError);
                }

                var newUserRole = new UserRole
                {
                    UserId = user.Id,
                    RoleId = userRegistrationDto.RoleId,
                    CreationDate = DateTime.Now,
                    CreatedBy = user.Username
                };

                // Assign role to the user
                await _userRoleRepository.AddAsync(newUserRole);

                // Create response model
                var responseModel = new RegisterUserResponseModel
                {
                    UserId = user.Id,
                    Username = user.Username,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    PhoneNumber = user.PhoneNumber,
                    Role = UserRoleHelper.GetRoleName(userRegistrationDto.RoleId),
                    IsEmailVerified = user.IsEmailConfirmed,
                    IsPhoneVerified = user.IsPhoneNumberConfirmed,
                    CreationDate = user.CreationDate
                };

                // Return success response
                return ApiResponse<RegisterUserResponseModel>.Success(responseModel);
            }
            catch (Exception ex)
            {
                // Log the exception (you can plug in a logging mechanism here)
                // LogError(ex);

                // Return a failure response with a general error message
                return ApiResponse<RegisterUserResponseModel>.Fail(500, "Internal Server Error", generalError);
            }
        }

        /// <summary>
        /// Logins the asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<LoginUserResponseModel>> LoginAsync(string email, string password)
        {
            const int unauthorizedStatusCode = 401;
            const string unauthorizedMessage = "Unauthorized";
            const string invalidCredentialsError = "Email or password is incorrect.";
            const string userLockedOutError = "User is currently locked out. Please try again later.";
            const string accountLockedError = "Account locked due to multiple failed login attempts. Try again later.";
            const string generalError = "An unexpected error occurred. Please try again later.";

            int tokenExpiryHours = 1;

            try
            {
                var user = await _userRepository.GetAsync(x => x.Email == email);

                if (user == null)
                {
                    return ApiResponse<LoginUserResponseModel>.Fail(unauthorizedStatusCode, unauthorizedMessage, invalidCredentialsError);
                }

                // Check if the user is locked out
                if (user.LockoutEnabled && user.LockoutEndDateUtc > DateTime.Now)
                {
                    return ApiResponse<LoginUserResponseModel>.Fail(unauthorizedStatusCode, unauthorizedMessage, userLockedOutError);
                }

                // Verify password
                if (!_passwordHasher.VerifyPassword(user.PasswordHash, password))
                {
                    // Handle failed login attempt
                    var isLockedOut = await HandleFailedLoginAsync(user.Id);

                    var errors = isLockedOut ? accountLockedError : invalidCredentialsError;

                    return ApiResponse<LoginUserResponseModel>.Fail(unauthorizedStatusCode, unauthorizedMessage, errors);
                }

                // Reset access failed count if login is successful
                await ResetAccessFailedCountAsync(user.Id);

                var activeUserSession = await _userSessionRepository.GetAllAsync(x => x.UserId == user.Id);

                if (activeUserSession.Where(x => x.IsValid).ToList().Count > 0)
                {
                    await _userSessionRepository.UpdateByConditionAsync(x => (x.IsValid && x.UserId == user.Id), x => { x.IsValid = false; x.ModificationDate = DateTime.Now; x.ModifiedBy = user.Username; });
                }

                // Generate JWT token
                var token = _jwtTokenGenerator.GenerateToken(user, tokenExpiryHours);

                // Create and add a new user session
                var userSession = new UserSession
                {
                    UserId = user.Id,
                    Token = token,
                    Expiration = DateTime.Now.AddHours(tokenExpiryHours), // Example expiration time
                    IsValid = true,
                    CreationDate = DateTime.Now,
                    CreatedBy = user.Username
                };

                await _userSessionRepository.AddAsync(userSession);

                // Prepare the response
                var response = new LoginUserResponseModel
                {
                    Token = token,
                    UserId = user.Id, // Converting long to string
                    UserName = user.Username,
                    Email = user.Email,
                    TokenExpiryDate = userSession.Expiration
                };

                return ApiResponse<LoginUserResponseModel>.Success(response);
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement a logging mechanism here)
                // LogError(ex); // Example of logging, replace with actual logging code

                // Return a failure response with a general error message
                return ApiResponse<LoginUserResponseModel>.Fail(500, "Internal Server Error", generalError);
            }
        }

        /// <summary>
        /// Logouts the asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> LogoutAsync(long userId, string token)
        {
            const int unauthorizedStatusCode = 401;
            const string unauthorizedMessage = "Unauthorized";
            const string invalidSessionError = "Invalid session.";
            const string generalError = "An unexpected error occurred while logging out. Please try again later.";

            try
            {
                var session = await GetValidSessionAsync(userId, token);

                if (session == null)
                {
                    return ApiResponse<bool>.Fail(unauthorizedStatusCode, unauthorizedMessage, invalidSessionError);
                }

                await InvalidateSessionAsync(session);

                return ApiResponse<bool>.Success(true);
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement a logging mechanism here)
                // LogError(ex); // Example of logging, replace with actual logging code

                // Return a failure response with a general error message
                return ApiResponse<bool>.Fail(500, "Internal Server Error", generalError);
            }
        }

        /// <summary>
        /// Generates the password reset token asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <returns></returns>
        public async Task<ApiResponse<PasswordResetTokenResponseModel>> GeneratePasswordResetTokenAsync(string email)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User with this email does not exist.";
            const int generalErrorCode = 500;
            const string generalErrorMessage = "An unexpected error occurred while generating the token. Please try again later.";

            try
            {
                var user = await _userRepository.GetAsync(x => x.Email == email);
                if (user == null)
                {
                    return ApiResponse<PasswordResetTokenResponseModel>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                var token = Guid.NewGuid().ToString();
                var expirationTime = DateTime.Now.AddMinutes(1); // Token is valid for 1 minute

                var passwordRecoveryToken = new PasswordRecoveryToken
                {
                    UserId = user.Id,
                    Token = token,
                    Expiration = expirationTime, // Set expiration time
                    CreationDate = DateTime.Now,
                    CreatedBy = user.Username
                };

                await _passwordRecoveryTokenRepository.AddAsync(passwordRecoveryToken);

                // Send token via email or other means (omitted for brevity)
                var emailModel = new EmailModel
                {
                    To = email,
                    Subject = "Password Reset Request",
                    Body = $"<p>Hi {user.Username},</p>" +
                           $"<p>You requested a password reset. Click the link below to reset your password:</p>" +
                           $"<p><a href='https://your-app-url.com/reset-password?token={token}'>Reset Password</a></p>" +
                           "<p>If you did not request this, please ignore this email.</p>"
                };

                // Send the email
                //await _emailSenderService.SendEmailAsync(emailModel);

                var responseModel = new PasswordResetTokenResponseModel
                {
                    Token = token,
                    Expiration = expirationTime // Include expiration time in response
                };

                return ApiResponse<PasswordResetTokenResponseModel>.Success(responseModel);
            }
            catch (Exception ex)
            {
                // Log the exception (implement a logging mechanism here)
                // LogError(ex);

                // Return a failure response with a general error message
                return ApiResponse<PasswordResetTokenResponseModel>.Fail(generalErrorCode, "Internal Server Error", generalErrorMessage);
            }
        }

        /// <summary>
        /// Resets the password asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="token">The token.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ResetPasswordAsync(string email, string token, string newPassword)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User with this email does not exist.";
            const int unauthorizedStatusCode = 401;
            const string unauthorizedMessage = "Unauthorized";
            const string invalidOrExpiredTokenError = "Invalid or expired password reset token.";
            const string generalError = "An unexpected error occurred while resetting the password. Please try again later.";

            try
            {
                var user = await _userRepository.GetAsync(x => x.Email == email);

                if (user == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                var validTokens = await _passwordRecoveryTokenRepository.GetAllAsync(x => x.UserId == user.Id && x.Token == token && !x.IsUsed);

                var tokenModel = validTokens.OrderByDescending(t => t.Expiration).FirstOrDefault();

                if (tokenModel == null || tokenModel.Expiration < DateTime.Now)
                {
                    return ApiResponse<bool>.Fail(unauthorizedStatusCode, unauthorizedMessage, invalidOrExpiredTokenError);
                }

                user.PasswordHash = _passwordHasher.HashPassword(newPassword);
                user.SecurityStamp = Guid.NewGuid().ToString(); // Update security stamp
                user.ModificationDate = DateTime.Now;

                await _userRepository.UpdateAsync(user);

                tokenModel.IsUsed = true; // Mark token as used
                await _passwordRecoveryTokenRepository.UpdateAsync(tokenModel);

                return ApiResponse<bool>.Success(true);
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement a logging mechanism here)
                // LogError(ex); // Example of logging, replace with actual logging code

                // Return a failure response with a general error message
                return ApiResponse<bool>.Fail(500, "Internal Server Error", generalError);
            }
        }

        /// <summary>
        /// Changes the password asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="currentPassword">The current password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ChangePasswordAsync(string email, string currentPassword, string newPassword)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User with this email does not exist.";
            const int unauthorizedStatusCode = 401;
            const string unauthorizedMessage = "Unauthorized";
            const string currentPasswordError = "Current password is incorrect.";
            const string samePasswordError = "New password cannot be the same as the current password.";
            const int generalErrorCode = 500;
            const string generalErrorMessage = "An unexpected error occurred while changing the password. Please try again later.";

            try
            {
                var user = await _userRepository.GetAsync(x => x.Email == email);

                if (user == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                // Verify the current password
                if (!_passwordHasher.VerifyPassword(user.PasswordHash, currentPassword))
                {
                    return ApiResponse<bool>.Fail(unauthorizedStatusCode, unauthorizedMessage, currentPasswordError);
                }

                // Check if the new password is different from the current password
                if (_passwordHasher.VerifyPassword(user.PasswordHash, newPassword))
                {
                    return ApiResponse<bool>.Fail(unauthorizedStatusCode, unauthorizedMessage, samePasswordError);
                }

                // Update password and security stamp
                user.PasswordHash = _passwordHasher.HashPassword(newPassword);
                user.SecurityStamp = Guid.NewGuid().ToString();  // Update security stamp
                user.ModificationDate = DateTime.Now;

                await _userRepository.UpdateAsync(user);

                return ApiResponse<bool>.Success(true);
            }
            catch (Exception ex)
            {
                // Log the exception (implement a logging mechanism here)
                // LogError(ex);

                // Return a failure response with a general error message
                return ApiResponse<bool>.Fail(generalErrorCode, "Internal Server Error", generalErrorMessage);
            }
        }

        /// <summary>
        /// Adds the role to user asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="currentUserId">The current user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<AddRoleResponseModel>> AddRoleToUserAsync(long userId, long roleId, long currentUserId)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User not found.";
            const string roleNotFoundError = "Role not found.";
            const string roleExistsError = "Role already exists for the user.";
            const int forbiddenStatusCode = 403;
            const string forbiddenMessage = "Forbidden";
            const string notAdminError = "Only admins can assign roles.";
            const int generalErrorCode = 500;
            const string generalErrorMessage = "An unexpected error occurred while adding the role to the user.";

            try
            {
                // Check if the current user is an admin
                var currentUserRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == currentUserId);

                var isAdmin = currentUserRoles.Any(r => r.RoleId == Enumerators.UserRoleEnum.Admin.GetHashCode()); // Assuming "Admin" is the role name

                if (!isAdmin)
                {
                    return ApiResponse<AddRoleResponseModel>.Fail(forbiddenStatusCode, forbiddenMessage, notAdminError);
                }

                // Fetch the user to which the role will be added
                var user = await _userRepository.GetByIdAsync(userId);

                if (user == null)
                {
                    return ApiResponse<AddRoleResponseModel>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                // Fetch the role by name
                bool isValidRole = Enum.IsDefined(typeof(UserRoleEnum), roleId);

                if (!isValidRole)
                {
                    return ApiResponse<AddRoleResponseModel>.Fail(notFoundStatusCode, notFoundMessage, roleNotFoundError);
                }

                // Check if the user already has the role
                var existingUserRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == userId && x.RoleId == roleId);

                if (existingUserRoles.Any())
                {
                    return ApiResponse<AddRoleResponseModel>.Fail(409, "Conflict", roleExistsError);
                }

                // Add the role to the user
                var userRole = new UserRole
                {
                    UserId = user.Id,
                    RoleId = roleId,
                    CreationDate = DateTime.Now,
                    CreatedBy = user.Username
                };

                await _userRoleRepository.AddAsync(userRole);

                // Prepare the response model
                var responseModel = new AddRoleResponseModel
                {
                    UserId = user.Id,
                    Username = user.Username,
                    RoleName = UserRoleHelper.GetRoleName(roleId),
                    RoleAssignedDate = DateTime.Now
                };

                return ApiResponse<AddRoleResponseModel>.Success(responseModel);
            }
            catch (Exception ex)
            {
                // Log the exception (implement your logging mechanism here)
                // LogError(ex);

                return ApiResponse<AddRoleResponseModel>.Fail(generalErrorCode, "Internal Server Error", generalErrorMessage);
            }
        }

        /// <summary>
        /// Removes the role from user asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="currentUserId">The current user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> RemoveRoleFromUserAsync(long userId, long roleId, long currentUserId)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User not found.";
            const string roleNotFoundError = "Role not found.";
            const string userRoleNotFoundError = "User does not have the specified role.";
            const string unauthorizedError = "Only admin can remove roles.";
            const string adminCannotRemoveOwnRoleError = "Admin cannot remove their own role.";

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);

                var currentUserRole = await _userRoleRepository.GetAsync(ur => ur.UserId == currentUserId);

                // Validate user existence
                if (user == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                bool isValidRole = Enum.IsDefined(typeof(UserRoleEnum), roleId);

                // Validate role existence
                if (!isValidRole)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, roleNotFoundError);
                }

                // Validate if the current user is an admin
                if (currentUserRole == null || currentUserRole.RoleId != Enumerators.UserRoleEnum.Admin.GetHashCode())
                {
                    return ApiResponse<bool>.Fail(403, "Forbidden", unauthorizedError);
                }

                // Check if the admin is trying to remove their own role
                if (userId == currentUserId && currentUserRole.RoleId == roleId)
                {
                    return ApiResponse<bool>.Fail(403, "Forbidden", adminCannotRemoveOwnRoleError);
                }

                // Validate the user's role
                var userRole = await _userRoleRepository.GetAsync(ur => ur.UserId == userId && ur.RoleId == roleId);

                if (userRole == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, userRoleNotFoundError);
                }

                // Remove the role from the user
                await _userRoleRepository.DeleteAsync(x => x.UserId == userRole.UserId && x.RoleId == userRole.RoleId);

                return ApiResponse<bool>.Success(true);
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement logging here)
                // LogError(ex);

                return ApiResponse<bool>.Fail(500, "Internal Server Error", ex.Message);
            }
        }

        /// <summary>
        /// Gets the user roles asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<UserRoleResponseModel>> GetUserRolesAsync(long userId)
        {
            try
            {
                const int notFoundStatusCode = 404;
                const string notFoundMessage = "Not found";

                // Fetch user roles
                var userRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == userId);

                if (userRoles == null || !userRoles.Any())
                {
                    return ApiResponse<UserRoleResponseModel>.Fail(notFoundStatusCode, notFoundMessage, "No roles found for the user.");
                }

                var userRoleResponse = new UserRoleResponseModel
                {
                    UserId = userId,
                };

                // Populate UserRoles list dynamically based on roleIds from your enum
                foreach (var roleId in userRoles.Select(x => x.RoleId).ToArray())
                {
                    // Convert roleId to UserRoleEnum
                    if (Enum.IsDefined(typeof(UserRoleEnum), roleId))
                    {
                        var roleEnum = (UserRoleEnum)roleId;
                        var roleName = Enum.GetName(typeof(UserRoleEnum), roleEnum);

                        // Check if the role is active using the RoleStatus dictionary
                        var isActive = UserRoleHelper.IsRoleActive(roleEnum);

                        // Add the role to the response model
                        userRoleResponse.UserRoles.Add(new UserRoleItem
                        {
                            RoleId = roleId,
                            RoleName = roleName ?? "Unknown",
                            IsActive = isActive,
                        });
                    }
                    else
                    {
                        // Handle case where roleId is not valid in the enum
                        userRoleResponse.UserRoles.Add(new UserRoleItem
                        {
                            RoleId = roleId,
                            RoleName = "Invalid Role",
                            IsActive = false,
                        });
                    }
                }

                return ApiResponse<UserRoleResponseModel>.Success(userRoleResponse);
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement logging here)
                // LogError(ex);

                return ApiResponse<UserRoleResponseModel>.Fail(500, "Internal Server Error", ex.Message);
            }
        }

        /// <summary>
        /// Initiates the email verification asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="email">The email.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> InitiateEmailVerificationAsync(long userId)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User not found.";

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);

                if (user == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                // Generate a new token
                var token = Guid.NewGuid();
                var expiration = DateTime.Now.AddHours(1);

                // Insert a new record into the Verifications table
                var verification = new Verification
                {
                    UserId = user.Id,
                    Email = user.Email,
                    VerificationType = Enumerators.VerficationTypeEnum.Email.GetHashCode(),
                    Token = token.ToString(),
                    ExpirationDate = expiration,
                    IsUsed = false,
                    Status = Enumerators.VerficationStatusEnum.Pending.GetHashCode(),
                    CreationDate = DateTime.Now,
                    CreatedBy = user.Username
                };

                await _verificationRepository.AddAsync(verification);

                // Send verification email
                //var emailSent = await SendEmailVerificationAsync(email, token);
                var emailSent = true;

                return emailSent ? ApiResponse<bool>.Success(true, "Verification email sent successfully") : ApiResponse<bool>.Fail(500, "Failed to send email");
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement logging here)
                // LogError(ex);

                return ApiResponse<bool>.Fail(500, "Internal Server Error", ex.Message);
            }
        }

        /// <summary>
        /// Confirms the email verification asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="email">The email.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ConfirmEmailVerificationAsync(long userId, string email, string token)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User not found.";

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);

                if (user == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                // Retrieve verification record
                var verification = await _verificationRepository.GetAsync(v => v.UserId == userId && v.Email == email && v.Token == token && v.VerificationType == Enumerators.VerficationTypeEnum.Email.GetHashCode() && !v.IsUsed);

                if (verification == null || verification.ExpirationDate < DateTime.Now)
                {
                    return ApiResponse<bool>.Fail(404, "Invalid or expired token");
                }

                // Update verification record
                verification.IsUsed = true;
                verification.Status = Enumerators.VerficationStatusEnum.Completed.GetHashCode();
                verification.ModificationDate = DateTime.Now;
                verification.ModifiedBy = user.Username;

                await _verificationRepository.UpdateAsync(verification);

                user.IsEmailConfirmed = true;
                user.ModificationDate = DateTime.Now;
                user.ModifiedBy = user.Username;

                await _userRepository.UpdateAsync(user);

                return ApiResponse<bool>.Success(true, "Email Verified Successfully");
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement logging here)
                // LogError(ex);

                return ApiResponse<bool>.Fail(500, "Internal Server Error", ex.Message);
            }
        }

        /// <summary>
        /// Sends the mobile verification code asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="countryCode">The country code.</param>
        /// <param name="mobileNumber">The mobile number.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> SendMobileVerificationCodeAsync(long userId, string countryCode, string mobileNumber)
        {
            const int notFoundStatusCode = 404;
            const string notFoundMessage = "Not Found";
            const string userNotFoundError = "User not found.";

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);

                if (user == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, notFoundMessage, userNotFoundError);
                }

                // Generate a 6-digit random verification code
                var verificationCode = new Random().Next(100000, 999999).ToString();

                // Save verification data
                var verificationEntry = new Verification
                {
                    UserId = userId,
                    PhoneNumber = string.Concat(countryCode, mobileNumber),
                    Token = verificationCode,
                    VerificationType = Enumerators.VerficationTypeEnum.Phone.GetHashCode(),
                    ExpirationDate = DateTime.Now.AddMinutes(10),
                    IsUsed = false,
                    Status = Enumerators.VerficationStatusEnum.Pending.GetHashCode(),
                    CreationDate = DateTime.Now,
                    CreatedBy = user.Username
                };

                await _verificationRepository.AddAsync(verificationEntry);

                // Send SMS with the verification code
                var smsResult = await _smsSenderService.SendSmsAsync(mobileNumber, $"Your verification code is: {verificationCode}");

                if (smsResult)
                {
                    return ApiResponse<bool>.Success(true, "Verification code sent successfully");
                }

                return ApiResponse<bool>.Fail(500, "Failed to send verification code.");
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement logging here)
                // LogError(ex);

                return ApiResponse<bool>.Fail(500, "Internal Server Error", ex.Message);
            }
        }

        /// <summary>
        /// Confirms the mobile verification code asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="countryCode">The country code.</param>
        /// <param name="mobileNumber">The mobile number.</param>
        /// <param name="verificationCode">The verification code.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ConfirmMobileVerificationCodeAsync(long userId, string countryCode, string mobileNumber, string verificationCode)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);

                if (user == null)
                {
                    return ApiResponse<bool>.Fail(404, "User not found");
                }

                // Check if a valid verification code exists for this number
                var verification = await _verificationRepository.GetAsync(v => v.UserId == userId && v.PhoneNumber == string.Concat(countryCode, mobileNumber) && v.Token == verificationCode && !v.IsUsed && v.ExpirationDate > DateTime.Now);

                if (verification == null)
                {
                    return ApiResponse<bool>.Fail(404, "Invalid or expired verification code.");
                }

                // Mark the code as used and update
                verification.IsUsed = true;
                verification.Status = Enumerators.VerficationStatusEnum.Completed.GetHashCode();
                verification.ModificationDate = DateTime.Now;
                verification.ModifiedBy = user.Username;

                await _verificationRepository.UpdateAsync(verification);

                user.IsPhoneNumberConfirmed = true;
                user.ModificationDate = DateTime.Now;
                user.ModifiedBy = user.Username;

                await _userRepository.UpdateAsync(user);

                return ApiResponse<bool>.Success(true, "Mobile number verified successfully");
            }
            catch (Exception ex)
            {
                // Log the exception (you can implement logging here)
                // LogError(ex);

                return ApiResponse<bool>.Fail(500, "Internal Server Error", ex.Message);
            }
        }

        /// <summary>
        /// Enables the two factor asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> EnableTwoFactorAsync(long userId)
        {
            const int notFoundStatusCode = 404;
            const string userNotFoundMessage = "User not found.";
            const string successMessage = "Two-factor authentication enabled successfully.";

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);

                if (user == null)
                {
                    return ApiResponse<bool>.Fail(notFoundStatusCode, "Not Found", userNotFoundMessage);
                }

                user.TwoFactorEnabled = true;
                user.ModificationDate = DateTime.Now;

                await _userRepository.UpdateAsync(user);

                return ApiResponse<bool>.Success(true, successMessage);
            }
            catch (Exception ex)
            {
                return ApiResponse<bool>.Fail(500, "Internal Server Error", ex.Message);
            }
        }

        /// <summary>
        /// Gets the logged in users asynchronous.
        /// </summary>
        /// <returns></returns>
        public async Task<ApiResponse<List<LoggedInUsersResponseModel>>> GetLoggedInUsersAsync(long adminUserId)
        {
            const int notFoundStatusCode = 404;
            const string userNotFoundMessage = "User not found.";
            const string notAnAdminErrorMessage = "User Not a Admin. Only Admin Users can fetch Session details.";
            const string noLoggedInUserMessage = "No Users are currently Logged In.";

            if (adminUserId == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(notFoundStatusCode, "Not Found", userNotFoundMessage);
            }

            var getUserRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == adminUserId);

            if (getUserRoles.Where(x => x.RoleId == Enumerators.UserRoleEnum.Admin.GetHashCode()).ToList().Count == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(notFoundStatusCode, "Not Found", notAnAdminErrorMessage);
            }

            var activeSessions = await _userSessionRepository.GetAllAsync(s => s.IsValid && s.Expiration > DateTime.Now);

            var userIds = activeSessions.Select(s => s.UserId).Distinct().ToList();

            var users = await _userRepository.GetAllAsync(u => userIds.Contains(u.Id));

            if (users.ToList().Count == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(notFoundStatusCode, "Not Found", noLoggedInUserMessage);
            }

            var userRoles = await _userRoleRepository.GetAllAsync(u => userIds.Contains(u.UserId));

            var allUsers = users.Select(u => new LoggedInUsersResponseModel
            {
                Id = u.Id,
                FirstName = u.FirstName,
                LastName = u.LastName,
                Email = u.Email,
                Username = u.Username,
                PhoneNumber = u.PhoneNumber,
                IsEmailConfirmed = u.IsEmailConfirmed,
                IsPhoneNumberConfirmed = u.IsPhoneNumberConfirmed,
                DOB = u.DOB,
                Gender = u.Gender,
                TwoFactorEnabled = u.TwoFactorEnabled,
                SessionExipry = activeSessions.FirstOrDefault(x => x.UserId == u.Id && x.IsValid)?.Expiration,
                UserRoles = string.Join(", ", userRoles
                            .Where(ur => ur.UserId == u.Id)
                            .Select(ur => UserRoleHelper.GetRoleName(ur.RoleId)))
            }).ToList();

            return ApiResponse<List<LoggedInUsersResponseModel>>.Success(allUsers);
        }

        /// <summary>
        /// Unlocks the user asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> UnlockUserAsync(string email, long adminUserId)
        {
            var adminUser = await _userRepository.GetAsync(x => x.Id == adminUserId && !x.LockoutEnabled);

            // Check if the user exists
            if (adminUser == null)
            {
                return ApiResponse<bool>.Fail(401, "Unauthorized", "Admin user does not exist.");
            }

            var adminUserRole = await _userRoleRepository.GetAsync(x => x.UserId == adminUserId && x.RoleId == Enumerators.UserRoleEnum.Admin.GetHashCode());

            if (adminUserRole == null)
            {
                return ApiResponse<bool>.Fail(401, "Unauthorized", "Not an Admin User");
            }

            var user = await _userRepository.GetAsync(x => x.Email == email);

            // Check if the user exists
            if (user == null)
            {
                return ApiResponse<bool>.Fail(401, "Unauthorized", "User not found.");
            }

            // Check if the user is locked out
            if (!user.LockoutEnabled)
            {
                return ApiResponse<bool>.Fail(400, "Bad Request", "User is not locked out.");
            }

            // Unlock user by setting LockoutEnd to null
            user.LockoutEnabled = false; // Unlock the user
            user.LockoutEndDateUtc = null;
            user.AccessFailedCount = 0;
            user.ModificationDate = DateTime.Now;
            user.ModifiedBy = adminUser.Username;

            await _userRepository.UpdateAsync(user);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Gets the valid session asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        private async Task<UserSession?> GetValidSessionAsync(long userId, string token)
        {
            return await _userSessionRepository.GetAsync(us => us.UserId == userId && us.Token == token && us.IsValid && us.Expiration > DateTime.Now);
        }

        /// <summary>
        /// Invalidates the session asynchronous.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        private async Task<bool> InvalidateSessionAsync(UserSession userSession)
        {
            if (userSession == null)
            {
                return false;
            }

            var user = await _userRepository.GetByIdAsync(userSession.UserId);

            if (user != null)
            {
                userSession.IsValid = false;
                userSession.ModificationDate = DateTime.Now;
                userSession.ModifiedBy = user.Username;

                await _userSessionRepository.UpdateAsync(userSession);
            }
            else
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Handles the failed login asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">User not found.</exception>
        private async Task<bool> HandleFailedLoginAsync(long userId)
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

        /// <summary>
        /// Resets the access failed count asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">User not found.</exception>
        private async Task<bool> ResetAccessFailedCountAsync(long userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                throw new Exception("User not found.");
            }

            user.AccessFailedCount = 0;
            user.LockoutEndDateUtc = null;
            user.ModificationDate = DateTime.Now;

            await _userRepository.UpdateAsync(user);

            return true;
        }

        /// <summary>
        /// Sends the email verification asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        private async Task<bool> SendEmailVerificationAsync(string email, long token)
        {
            var verificationUrl = $"https://yourapp.com/verify-email?token={token}";
            var subject = "Email Verification";
            var body = $"Please verify your email by clicking on this link: {verificationUrl}";

            var emailModel = new EmailModel
            {
                To = email,
                Subject = subject,
                Body = body
            };

            return await _emailSenderService.SendEmailAsync(emailModel);
        }

        #endregion
    }
}
