using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;
using SportifyX.Application.Services.Common.Interface;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Helpers;
using SportifyX.Domain.Interfaces;
using SportifyX.Domain.Settings;
using static SportifyX.Domain.Helpers.Enumerators;

namespace SportifyX.Application.Services
{
    /// <summary>
    /// AuthService
    /// </summary>
    /// <seealso cref="SportifyX.Application.Services.Interface.IAuthService" />
    public class AuthService(
        IGenericRepository<User> userRepository,
        IGenericRepository<UserSession> userSessionRepository,
        IGenericRepository<UserRole> userRoleRepository,
        IGenericRepository<Verification> verificationRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenGenerator jwtTokenGenerator,
        ISmsSenderService smsSenderService,
        ICommonService commonService,
        IOptions<EmailSettingsApi> options) : IAuthService
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
        /// The SMS sender service  
        /// </summary>
        private readonly ISmsSenderService _smsSenderService = smsSenderService;

        /// <summary>
        /// The common service
        /// </summary>
        private readonly ICommonService _commonService = commonService;

        /// <summary>
        /// The settings
        /// </summary>
        private readonly EmailSettingsApi _emailSettingsApi = options.Value;

        #endregion

        #region Public Methods

        #region New User Registration

        /// <summary>
        /// Registers the user asynchronous.
        /// </summary>
        /// <param name="userRegistrationDto">The user registration dto.</param>
        /// <returns></returns>
        public async Task<ApiResponse<RegisterUserResponseModel>> RegisterUserAsync(UserRegistrationDto userRegistrationDto)
        {
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

            // Check if the role exists
            var isValidRole = Enum.IsDefined(typeof(UserRoleEnum), userRegistrationDto.RoleId);

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
            const int tokenExpiryMinutes = 5; // 5 minute expiry

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
            var token = _jwtTokenGenerator.GenerateToken(user, tokenExpiryMinutes);

            // Create and add a new user session
            var userSession = new UserSession
            {
                UserId = user.Id,
                Token = token,
                Expiration = DateTime.UtcNow.AddMinutes(tokenExpiryMinutes),
                IsValid = true,
                CreationDate = DateTime.UtcNow,
                CreatedBy = user.Username
            };

            await _userSessionRepository.AddAsync(userSession);

            // Prepare the response
            var response = new LoginUserResponseModel
            {
                Token = token,
                UserId = user.Id,
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
                VerificationType = VerificationTypeEnum.Email.GetHashCode(),
                Token = token.ToString(),
                ExpirationDate = expiration,
                IsUsed = false,
                Status = VerificationStatusEnum.Pending.GetHashCode(),
                CreationDate = DateTime.UtcNow,
                CreatedBy = user.Username
            };

            await _verificationRepository.AddAsync(verification);

            // Send verification email
            var verificationUrl = $"https://localhost:44356/api/auth/verify-email/confirm?token={token}";
            const string subject = "Email Verification";
            var body = $"Please verify your email by clicking on this link: {verificationUrl}";

            //var toEmailAndName = new Dictionary<string, string> { { user.FirstName, user.Email } };
            var toEmailAndName = new Dictionary<string, string> { { user.FirstName, "vanwalamufaddal@gmail.com" } };
            var ccEmailAndName = new Dictionary<string, string> { { _emailSettingsApi.FromName, _emailSettingsApi.FromEmail } };

            // Send the email
            var emailSent = await _commonService.SendEmail(toEmailAndName, ccEmailAndName, null, subject, body);

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
        /// <param name="token">The token.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> ConfirmEmailVerificationAsync(string token)
        {
            // Retrieve verification record
            var verification = await _verificationRepository.GetAsync(v => v.Token == token && v.VerificationType == VerificationTypeEnum.Email.GetHashCode() && !v.IsUsed);

            if (verification == null || verification.ExpirationDate < DateTime.UtcNow)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("InvalidTokenErrorMessage"));
            }

            var user = await _userRepository.GetByIdAsync(verification.UserId);

            if (user == null)
            {
                return ApiResponse<bool>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            // Update verification record
            verification.IsUsed = true;
            verification.Status = VerificationStatusEnum.Completed.GetHashCode();
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
                VerificationType = VerificationTypeEnum.Phone.GetHashCode(),
                ExpirationDate = DateTime.UtcNow.AddMinutes(10),
                IsUsed = false,
                Status = VerificationStatusEnum.Pending.GetHashCode(),
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

            return ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("FailedToSendVerificationCode"));
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
            verification.Status = VerificationStatusEnum.Completed.GetHashCode();
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

        #endregion

        #region Private Methods

        #region Reset Access Failed Count for User

        /// <summary>
        /// Resets the access failed count asynchronous.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception"></exception>
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
        /// <param name="userSession">The user session.</param>
        /// <returns></returns>
        private async Task<bool> InvalidateSessionAsync(UserSession userSession)
        {
            if (userSession.UserId == 0)
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

        #endregion
    }
}
