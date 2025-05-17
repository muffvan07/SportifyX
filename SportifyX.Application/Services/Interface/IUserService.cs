using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;

namespace SportifyX.Application.Services.Interface
{
    /// <summary>
    /// IUserService
    /// </summary>
    public interface IUserService
    {
        /// <summary>
        /// Gets all registered users asynchronous.
        /// </summary>
        /// <param name="adminUserId">The admin user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<List<RegisteredUserResponseModel>>> GetAllRegisteredUsersAsync(long adminUserId);

        /// <summary>
        /// Gets the logged-in users asynchronous.
        /// </summary>
        /// <param name="adminUserId">The admin user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<List<LoggedInUsersResponseModel>>> GetLoggedInUsersAsync(long adminUserId);

        /// <summary>
        /// Unlocks the user asynchronous.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="adminUserId">The admin user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> UnlockUserAsync(string email, long adminUserId);

        /// <summary>
        /// Adds the role to user asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="roleId">The role identifier.</param>
        /// <param name="currentUserId">The current user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<AddRoleResponseModel>> AddRoleToUserAsync(long userId, long roleId, long currentUserId);

        /// <summary>
        /// Gets the user roles asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<UserRoleResponseModel>> GetUserRolesAsync(long userId);
        
        /// <summary>
        /// Removes the role from user asynchronous.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="roleId">The role identifier.</param>
        /// <param name="currentUserId">The current user identifier.</param>
        /// <returns></returns>
        Task<ApiResponse<bool>> RemoveRoleFromUserAsync(long userId, long roleId, long currentUserId);
    }
}
