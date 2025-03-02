using Microsoft.AspNetCore.Http;
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
    /// <seealso cref="SportifyX.Application.Services.Interface.IUserService" />
    public class UserService(
        IGenericRepository<User> userRepository,
        IGenericRepository<UserSession> userSessionRepository,
        IGenericRepository<UserRole> userRoleRepository,
        IGenericRepository<PasswordRecoveryToken> passwordRecoveryTokenRepository,
        IGenericRepository<Verification> verificationRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenGenerator jwtTokenGenerator,
        IBrevoEmailService emailSenderService,
        ISmsSenderService smsSenderService,
        IExceptionHandlingService exceptionLoggingService) : IUserService
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
        private readonly IBrevoEmailService _emailSenderService = emailSenderService;

        /// <summary>
        /// The SMS sender service  
        /// </summary>
        private readonly ISmsSenderService _smsSenderService = smsSenderService;

        /// <summary>
        /// The exception logging service
        /// </summary>
        private readonly IExceptionHandlingService _exceptionLoggingService = exceptionLoggingService;

        #endregion

        #region Action Methods

        #region New User Registration

        /// <summary>
        /// Registers the user asynchronous.
        /// </summary>
        /// <param name="userRegistrationDto">The user registration dto.</param>
        /// <returns></returns>
        public async Task<ApiResponse<RegisterUserResponseModel>> RegisterUserAsync(UserRegistrationDto userRegistrationDto)
        {
            var pUserId = "0";
            var puserName = userRegistrationDto.Username;

            // Check if a user with the same email already exists
            var existingUser = await _userRepository.GetAsync(x => x.Email == userRegistrationDto.Email);

            if (existingUser != null)
            {
                return ApiResponse<RegisterUserResponseModel>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("UserExistsErrorMessage"));
            }

            //throw new InvalidOperationException("This is a test exception");

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
                CreationDate = DateTime.UtcNow,
                CreatedBy = userRegistrationDto.Username
            };

            await _userRepository.AddAsync(user);

            pUserId = user.Id.ToString();

            // Check if the role exists
            bool isValidRole = Enum.IsDefined(typeof(UserRoleEnum), userRegistrationDto.RoleId);

            if (!isValidRole)
            {
                return ApiResponse<RegisterUserResponseModel>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("RoleDoesNotExistErrorMessage"));
            }

            var newUserRole = new UserRole
            {
                UserId = user.Id,
                RoleId = userRegistrationDto.RoleId,
                CreationDate = DateTime.UtcNow,
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

        #endregion

        #region User Login

        /// <summary>
        /// Logins the asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public async Task<ApiResponse<LoginUserResponseModel>> LoginAsync(string email, string password)
        {
            int tokenExpiryHours = 1;

            var user = await _userRepository.GetAsync(x => x.Email == email);

            if (user == null)
            {
                return ApiResponse<LoginUserResponseModel>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("InvalidCredentialsErrorMessage"));
            }

            // Check if the user is locked out
            if (user.LockoutEnabled && user.LockoutEndDateUtc > DateTime.UtcNow)
            {
                return ApiResponse<LoginUserResponseModel>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("UserLockedOutErrorMessage"));
            }

            // Verify password
            if (!_passwordHasher.VerifyPassword(user.PasswordHash, password))
            {
                // Handle failed login attempt
                var isLockedOut = await HandleFailedLoginAsync(user);

                var errors = isLockedOut ? ErrorMessageHelper.GetErrorMessage("AccountLockedErrorMessage") : ErrorMessageHelper.GetErrorMessage("InvalidCredentialsErrorMessage");

                return ApiResponse<LoginUserResponseModel>.Fail(StatusCodes.Status401Unauthorized, errors);
            }

            // Reset access failed count if login is successful
            await ResetAccessFailedCountAsync(user);

            var activeUserSession = await _userSessionRepository.GetAllAsync(x => x.UserId == user.Id);

            if (activeUserSession.Where(x => x.IsValid).ToList().Count > 0)
            {
                await _userSessionRepository.UpdateByConditionAsync(x => (x.IsValid && x.UserId == user.Id), x => { x.IsValid = false; x.ModificationDate = DateTime.UtcNow; x.ModifiedBy = user.Username; });
            }

            // Generate JWT token
            var token = _jwtTokenGenerator.GenerateToken(user, tokenExpiryHours);

            // Create and add a new user session
            var userSession = new UserSession
            {
                UserId = user.Id,
                Token = token,
                Expiration = DateTime.UtcNow.AddHours(tokenExpiryHours), // Example expiration time
                IsValid = true,
                CreationDate = DateTime.UtcNow,
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

        #endregion

        #region User Logout

        /// <summary>
        /// Logouts the asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> LogoutAsync(long userId, string token)
        {
            var session = await GetValidSessionAsync(userId, token);

            if (session == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("InvalidSessionErrorMessage"));
            }

            await InvalidateSessionAsync(session);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Get Logged In Users

        /// <summary>
        /// Gets the logged in users asynchronous.
        /// </summary>
        /// <returns></returns>
        public async Task<ApiResponse<List<LoggedInUsersResponseModel>>> GetLoggedInUsersAsync(long adminUserId)
        {
            if (adminUserId == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            var getUserRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == adminUserId);

            if (getUserRoles.Where(x => x.RoleId == Enumerators.UserRoleEnum.Admin.GetHashCode()).ToList().Count == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("NotAdminToFetchSessionErrorMessage"));
            }

            var activeSessions = await _userSessionRepository.GetAllAsync(s => s.IsValid && s.Expiration > DateTime.UtcNow);

            var userIds = activeSessions.Select(s => s.UserId).Distinct().ToList();

            var users = await _userRepository.GetAllAsync(u => userIds.Contains(u.Id));

            if (users.ToList().Count == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("NoUsersLoggedInErrorMessage"));
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

        #endregion

        #region Unlock User

        /// <summary>
        /// Unlocks the user asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="adminUserId">The admin user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> UnlockUserAsync(string email, long adminUserId)
        {
            var adminUser = await _userRepository.GetAsync(x => x.Id == adminUserId && !x.LockoutEnabled);

            // Check if the user exists
            if (adminUser == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("AdminUserNotFoundErrorMessage"));
            }

            var adminUserRole = await _userRoleRepository.GetAsync(x => x.UserId == adminUserId && x.RoleId == Enumerators.UserRoleEnum.Admin.GetHashCode());

            if (adminUserRole == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("NotAnAdminErrorMessage"));
            }

            var user = await _userRepository.GetAsync(x => x.Email == email);

            // Check if the user exists
            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status401Unauthorized, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Check if the user is locked out
            if (!user.LockoutEnabled)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status400BadRequest, ErrorMessageHelper.GetErrorMessage("UserNotLockedOutErrorMessage"));
            }

            // Unlock user by setting LockoutEnd to null
            user.LockoutEnabled = false; // Unlock the user
            user.LockoutEndDateUtc = null;
            user.AccessFailedCount = 0;
            user.ModificationDate = DateTime.UtcNow;
            user.ModifiedBy = adminUser.Username;

            await _userRepository.UpdateAsync(user);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Add User Role

        /// <summary>
        /// Adds the role to user asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="roleId">The role identifier.</param>
        /// <param name="currentUserId">The current user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<AddRoleResponseModel>> AddRoleToUserAsync(long userId, long roleId, long currentUserId)
        {
            var currentUserRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == currentUserId);

            var isAdmin = currentUserRoles.Any(r => r.RoleId == Enumerators.UserRoleEnum.Admin.GetHashCode()); // Assuming "Admin" is the role name

            if (!isAdmin)
            {
                return ApiResponse<AddRoleResponseModel>.Fail(StatusCodes.Status403Forbidden, ErrorMessageHelper.GetErrorMessage("AdminCanAssignRoleErrorMessage"));
            }

            // Fetch the user to which the role will be added
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                return ApiResponse<AddRoleResponseModel>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Fetch the role by name
            bool isValidRole = Enum.IsDefined(typeof(UserRoleEnum), roleId);

            if (!isValidRole)
            {
                return ApiResponse<AddRoleResponseModel>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("RoleDoesNotExistErrorMessage"));
            }

            // Check if the user already has the role
            var existingUserRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == userId && x.RoleId == roleId);

            if (existingUserRoles.Any())
            {
                return ApiResponse<AddRoleResponseModel>.Fail(StatusCodes.Status409Conflict, ErrorMessageHelper.GetErrorMessage("RoleExistsErrorMessage"));
            }

            // Add the role to the user
            var userRole = new UserRole
            {
                UserId = user.Id,
                RoleId = roleId,
                CreationDate = DateTime.UtcNow,
                CreatedBy = user.Username
            };

            await _userRoleRepository.AddAsync(userRole);

            // Prepare the response model
            var responseModel = new AddRoleResponseModel
            {
                UserId = user.Id,
                Username = user.Username,
                RoleName = UserRoleHelper.GetRoleName(roleId),
                RoleAssignedDate = DateTime.UtcNow
            };

            return ApiResponse<AddRoleResponseModel>.Success(responseModel);
        }

        #endregion

        #region Remove User Role

        /// <summary>
        /// Removes the role from user asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="roleId">The role identifier.</param>
        /// <param name="currentUserId">The current user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> RemoveRoleFromUserAsync(long userId, long roleId, long currentUserId)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            var currentUserRole = await _userRoleRepository.GetAsync(ur => ur.UserId == currentUserId);

            // Validate user existence
            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            bool isValidRole = Enum.IsDefined(typeof(UserRoleEnum), roleId);

            // Validate role existence
            if (!isValidRole)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("RoleDoesNotExistErrorMessage"));
            }

            // Validate if the current user is an admin
            if (currentUserRole == null || currentUserRole.RoleId != Enumerators.UserRoleEnum.Admin.GetHashCode())
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status403Forbidden, ErrorMessageHelper.GetErrorMessage("AdminCanRemoveRoleErrorMessage"));
            }

            // Check if the admin is trying to remove their own role
            if (userId == currentUserId && currentUserRole.RoleId == roleId)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status403Forbidden, ErrorMessageHelper.GetErrorMessage("AdminCannotRemoveOwnRoleErrorMessage"));
            }

            // Validate the user's role
            var userRole = await _userRoleRepository.GetAsync(ur => ur.UserId == userId && ur.RoleId == roleId);

            if (userRole == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserRolesNotFoundErrorMessage"));
            }

            // Remove the role from the user
            await _userRoleRepository.DeleteAsync(x => x.UserId == userRole.UserId && x.RoleId == userRole.RoleId);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Get User Roles

        /// <summary>
        /// Gets the user roles asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<UserRoleResponseModel>> GetUserRolesAsync(long userId)
        {
            var user = await _userRepository.GetAsync(x => x.Id == userId);

            if (user == null)
            {
                return ApiResponse<UserRoleResponseModel>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Fetch user roles
            var userRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == userId);

            if (userRoles == null || !userRoles.Any())
            {
                return ApiResponse<UserRoleResponseModel>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserRolesNotFoundErrorMessage"));
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

        #endregion

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
            var subject = "Password Reset Request";
            var body = $"<p>Hi {user.Username},</p>" +
                       $"<p>You requested a password reset. Click the link below to reset your password:</p>" +
                       $"<p><a href='https://your-app-url.com/reset-password?token={token}'>Reset Password</a></p>" +
                       "<p>If you did not request this, please ignore this email.</p>";

            // Send the email
            bool emailSent = await SendEmail(toEmailAndName, null, null, subject, body);

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

        #region Initiate Email Verification

        /// <summary>
        /// Initiates the email verification asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> InitiateEmailVerificationAsync(long userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Generate a new token
            var token = Guid.NewGuid();
            var expiration = DateTime.UtcNow.AddHours(1);

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
                CreationDate = DateTime.UtcNow,
                CreatedBy = user.Username
            };

            await _verificationRepository.AddAsync(verification);

            // Send verification email
            var verificationUrl = $"https://yourapp.com/verify-email?token={token}";
            var subject = "Email Verification";
            var body = $"Please verify your email by clicking on this link: {verificationUrl}";

            var toEmailAndName = new Dictionary<string, string> { { user.FirstName, user.Email } };
            var ccEmailAndName = new Dictionary<string, string> { { "Mufaddal", "vanwalamufaddal@gmail.com" } };

            // Send the email
            bool emailSent = await SendEmail(toEmailAndName, ccEmailAndName, null, subject, body);

            if (!emailSent)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
            }

            return emailSent ? ApiResponse<bool>.Success(true) : ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("FailedToSendEmailErrorMessage"));
        }

        #endregion

        #region Confirm Email Verification

        /// <summary>
        /// Confirms the email verification asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="email">The email.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ConfirmEmailVerificationAsync(long userId, string email, string token)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Retrieve verification record
            var verification = await _verificationRepository.GetAsync(v => v.UserId == userId && v.Email == email && v.Token == token && v.VerificationType == Enumerators.VerficationTypeEnum.Email.GetHashCode() && !v.IsUsed);

            if (verification == null || verification.ExpirationDate < DateTime.UtcNow)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("InvalidTokenErrorMessage"));
            }

            // Update verification record
            verification.IsUsed = true;
            verification.Status = Enumerators.VerficationStatusEnum.Completed.GetHashCode();
            verification.ModificationDate = DateTime.UtcNow;
            verification.ModifiedBy = user.Username;

            await _verificationRepository.UpdateAsync(verification);

            user.IsEmailConfirmed = true;
            user.ModificationDate = DateTime.UtcNow;
            user.ModifiedBy = user.Username;

            await _userRepository.UpdateAsync(user);

            return ApiResponse<bool>.Success(true);
        }

        #endregion

        #region Send Mobile Verification

        /// <summary>
        /// Sends the mobile verification code asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="countryCode">The country code.</param>
        /// <param name="mobileNumber">The mobile number.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> SendMobileVerificationCodeAsync(long userId, string countryCode, string mobileNumber)
        {
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
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
                ExpirationDate = DateTime.UtcNow.AddMinutes(10),
                IsUsed = false,
                Status = Enumerators.VerficationStatusEnum.Pending.GetHashCode(),
                CreationDate = DateTime.UtcNow,
                CreatedBy = user.Username
            };

            await _verificationRepository.AddAsync(verificationEntry);

            // Send SMS with the verification code
            var smsResult = await _smsSenderService.SendSmsAsync(mobileNumber, $"Your verification code is: {verificationCode}");

            if (smsResult)
            {
                return ApiResponse<bool>.Success(true);
            }

            return ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("FailedToSendVerficationCode"));
        }

        #endregion

        #region Confirm Mobile Verification

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
            var user = await _userRepository.GetByIdAsync(userId);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Check if a valid verification code exists for this number
            var verification = await _verificationRepository.GetAsync(v => v.UserId == userId && v.PhoneNumber == string.Concat(countryCode, mobileNumber) && v.Token == verificationCode && !v.IsUsed && v.ExpirationDate > DateTime.UtcNow);

            if (verification == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("InvalidTokenErrorMessage"));
            }

            // Mark the code as used and update
            verification.IsUsed = true;
            verification.Status = Enumerators.VerficationStatusEnum.Completed.GetHashCode();
            verification.ModificationDate = DateTime.UtcNow;
            verification.ModifiedBy = user.Username;

            await _verificationRepository.UpdateAsync(verification);

            user.IsPhoneNumberConfirmed = true;
            user.ModificationDate = DateTime.UtcNow;
            user.ModifiedBy = user.Username;

            await _userRepository.UpdateAsync(user);

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

        #endregion

        #region Private Methods

        #region Get Valid Session

        /// <summary>
        /// Gets the valid session asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        private async Task<UserSession?> GetValidSessionAsync(long userId, string token)
        {
            return await _userSessionRepository.GetAsync(us => us.UserId == userId && us.Token == token && us.IsValid && us.Expiration > DateTime.UtcNow);
        }

        #endregion

        #region Invalidate Session

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
                userSession.ModificationDate = DateTime.UtcNow;
                userSession.ModifiedBy = user.Username;

                await _userSessionRepository.UpdateAsync(userSession);
            }
            else
            {
                return false;
            }

            return true;
        }

        #endregion

        #region Handle Failed Login

        /// <summary>
        /// Handles the failed login asynchronous.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        private async Task<bool> HandleFailedLoginAsync(User user)
        {
            try
            {
                user.AccessFailedCount += 1;

                if (user.AccessFailedCount >= 5)
                {
                    user.LockoutEnabled = true;
                    user.LockoutEndDateUtc = DateTime.UtcNow.AddMinutes(15); // Lockout for 15 minutes
                }

                await _userRepository.UpdateAsync(user);

                return user.LockoutEnabled;
            }
            catch (Exception ex)
            {
                // Log the exception (implement a logging mechanism here)
                // LogError(ex);

                // Return a failure response with a general error message
                throw new Exception(ErrorMessageHelper.GetErrorMessage(ex.Message));
            }
        }

        #endregion

        #region Reset Access Failed Count for User

        /// <summary>
        /// Resets the access failed count asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">User not found.</exception>
        private async Task<bool> ResetAccessFailedCountAsync(User user)
        {
            try
            {
                user.AccessFailedCount = 0;
                user.LockoutEndDateUtc = null;
                user.ModificationDate = DateTime.UtcNow;
                user.ModifiedBy = user.Username;

                await _userRepository.UpdateAsync(user);

                return true;
            }
            catch (Exception ex)
            {
                // Log the exception (implement a logging mechanism here)
                // LogError(ex);

                // Return a failure response with a general error message
                throw new Exception(ErrorMessageHelper.GetErrorMessage(ex.Message));
            }
        }

        #endregion

        #region Send Email

        /// <summary>
        /// Sends the email.
        /// </summary>
        /// <param name="to">To.</param>
        /// <param name="cc">The cc.</param>
        /// <param name="bcc">The BCC.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="body">The body.</param>
        /// <returns></returns>
        private async Task<bool> SendEmail(Dictionary<string, string> to, Dictionary<string, string>? cc, Dictionary<string, string>? bcc, string subject, string body)
        {
            var senderEmailsAndNames = new Dictionary<string, string>
            {
                { "SportifyX", "vanwalamufaddal@gmail.com" }
            };

            try
            {
                var response = await _emailSenderService.SendEmailAsync(senderEmailsAndNames, to, cc, bcc, subject, body);

                if (!response.IsSuccessStatusCode) return false;
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }

        #endregion

        #endregion
    }
}
