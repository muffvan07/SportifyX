﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using SportifyX.Application.DTOs.User;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.ResponseModels.User;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Helpers;

namespace SportifyX.API.Controllers
{
    /// <summary>
    /// UserController
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Mvc.ControllerBase" />
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(
        IUserService authService, 
        IExceptionHandlingService exceptionHandlingService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The user service
        /// </summary>
        private readonly IUserService _userService = authService;

        /// <summary>
        /// The exception handling service
        /// </summary>
        private readonly IExceptionHandlingService _exceptionHandlingService = exceptionHandlingService;

        #endregion

        #region Methods

        #region All Users

        /// <summary>
        /// Gets the list of all registered users. Admin access only.
        /// </summary>
        /// <param name="adminUserId">The admin user identifier.</param>
        /// <returns></returns>
        [HttpGet("all")]
        public async Task<IActionResult> GetAllRegisteredUsers([FromQuery] long adminUserId)
        {
            try
            {
                var response = await _userService.GetAllRegisteredUsersAsync(adminUserId);

                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<List<RegisteredUserResponseModel>>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Get Logged in Users

        /// <summary>
        /// Gets the logged-in users.
        /// </summary>
        /// <returns></returns>
        [HttpGet("active-sessions")]
        public async Task<IActionResult> GetLoggedInUsers(long adminUserId)
        {
            try
            {
                var response = await _userService.GetLoggedInUsersAsync(adminUserId);

                // Return based on response status
                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Unlock User

        /// <summary>
        /// Unlocks the user.
        /// </summary>
        /// <param name="unlockUserDto">The unlock user dto.</param>
        /// <returns></returns>
        [HttpPost("unlock")]
        public async Task<IActionResult> UnlockUser([FromBody] UnlockUserDto unlockUserDto)
        {
            try
            {
                var response = await _userService.UnlockUserAsync(unlockUserDto.Email, unlockUserDto.AdminUserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Add User Role

        /// <summary>
        /// Adds the user role.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("roles/add")]
        public async Task<IActionResult> AddUserRole([FromBody] AddRoleDto dto)
        {
            try
            {
                var response = await _userService.AddRoleToUserAsync(dto.UserId, dto.RoleId, dto.CurrentUserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Get User Roles

        /// <summary>
        /// Gets the user roles.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        [HttpGet("roles")]
        public async Task<IActionResult> GetUserRoles(long userId)
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
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #region Remove User Role

        /// <summary>
        /// Removes the user role.
        /// </summary>
        /// <param name="dto">The dto.</param>
        /// <returns></returns>
        [HttpPost("roles/remove")]
        public async Task<IActionResult> RemoveUserRole([FromBody] RemoveRoleDto dto)
        {
            try
            {
                var response = await _userService.RemoveRoleFromUserAsync(dto.UserId, dto.RoleId, dto.CurrentUserId);

                if (response.StatusCode == StatusCodes.Status200OK)
                {
                    return Ok(response);
                }

                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                // Log the exception
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion

        #endregion
    }
}
