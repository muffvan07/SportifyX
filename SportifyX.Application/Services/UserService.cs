using Microsoft.AspNetCore.Http;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;
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
        IGenericRepository<UserRole> userRoleRepository) : IUserService
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

        #endregion

        #region Action Methods

        #region Get All Registered Users

        /// <summary>
        /// Gets all registered users. Only accessible by Admin.
        /// </summary>
        /// <param name="adminUserId">The admin user ID making the request.</param>
        /// <returns></returns>
        public async Task<ApiResponse<List<RegisteredUserResponseModel>>> GetAllRegisteredUsersAsync(long adminUserId)
        {
            // Check if the requesting user is an admin
            var userRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == adminUserId);
            var isAdmin = userRoles.Any(r => r.RoleId == UserRoleEnum.Admin.GetHashCode());

            if (!isAdmin)
            {
                return ApiResponse<List<RegisteredUserResponseModel>>.Fail(StatusCodes.Status403Forbidden, ErrorMessageHelper.GetErrorMessage("NotAnAdminErrorMessage"));
            }

            // Fetch all users and all user-role mappings
            var users = await _userRepository.GetAllAsync();
            var allUserRoles = await _userRoleRepository.GetAllAsync();

            // Map users with their roles
            var result = users.Select(user =>
            {
                // Get all role IDs assigned to this user
                var roleIdsForUser = allUserRoles
                    .Where(ur => ur.UserId == user.Id)
                    .Select(ur => ur.RoleId)
                    .Distinct()
                    .ToList();

                // Convert role IDs to role names using the enum helper
                var roleNames = roleIdsForUser
                    .Select(UserRoleHelper.GetRoleName)
                    .ToList();

                return new RegisteredUserResponseModel
                {
                    UserId = user.Id,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Username = user.Username,
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    Dob = user.DOB,
                    Gender = user.Gender,
                    CreationDate = user.CreationDate,
                    IsEmailConfirmed = user.IsEmailConfirmed,
                    IsPhoneNumberConfirmed = user.IsPhoneNumberConfirmed,
                    Roles = roleNames
                };
            }).ToList();

            return ApiResponse<List<RegisteredUserResponseModel>>.Success(result);
        }

        #endregion

        #region Get Logged In Users

        /// <summary>
        /// Gets the logged-in users asynchronous.
        /// </summary>
        /// <returns></returns>
        public async Task<ApiResponse<List<LoggedInUsersResponseModel>>> GetLoggedInUsersAsync(long adminUserId)
        {
            if (adminUserId == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("UserNotFoundErrorMessage"));
            }

            var getUserRoles = await _userRoleRepository.GetAllAsync(x => x.UserId == adminUserId);

            if (getUserRoles.Where(x => x.RoleId == UserRoleEnum.Admin.GetHashCode()).ToList().Count == 0)
            {
                return ApiResponse<List<LoggedInUsersResponseModel>>.Fail(StatusCodes.Status404NotFound, ErrorMessageHelper.GetErrorMessage("NotAdminToFetchSessionErrorMessage"));
            }

            var activeSessions = await _userSessionRepository.GetAllAsync(s => s.IsValid && s.Expiration > DateTime.UtcNow);

            var userSessions = activeSessions.ToList();
            var userIds = userSessions.Select(s => s.UserId).Distinct().ToList();

            var users = await _userRepository.GetAllAsync(u => userIds.Contains(u.Id));

            if (users != null && !users.Any())
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
                SessionExipry = userSessions.FirstOrDefault(x => x.UserId == u.Id && x.IsValid)?.Expiration,
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

            var adminUserRole = await _userRoleRepository.GetAsync(x => x.UserId == adminUserId && x.RoleId == UserRoleEnum.Admin.GetHashCode());

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

            var isAdmin = currentUserRoles.Any(r => r.RoleId == UserRoleEnum.Admin.GetHashCode()); // Assuming "Admin" is the role name

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
            var isValidRole = Enum.IsDefined(typeof(UserRoleEnum), roleId);

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
            if (currentUserRole == null || currentUserRole.RoleId != UserRoleEnum.Admin.GetHashCode())
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

        #endregion
    }
}
