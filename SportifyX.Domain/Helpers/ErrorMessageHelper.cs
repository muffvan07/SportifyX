namespace SportifyX.Domain.Helpers
{
    /// <summary>
    /// A simple helper class to store and retrieve predefined error messages
    /// </summary>
    public static class ErrorMessageHelper
    {
        // Dictionary to store error codes and messages
        private static readonly Dictionary<string, string> ErrorMessages = new Dictionary<string, string>
        {
            ["GeneralErrorMessage"] = "An unexpected error occurred. Please try again later.",
            ["UserExistsErrorMessage"] = "A user with this email already exists.",
            ["RoleDoesNotExistErrorMessage"] = "The specified role does not exist.",
            ["InvalidCredentialsErrorMessage"] = "Email or Password is incorrect.",
            ["UserLockedOutErrorMessage"] = "User is currently locked out. Please try again later.",
            ["AccountLockedErrorMessage"] = "Account locked due to multiple failed login attempts. Try again later.",
            ["InvalidSessionErrorMessage"] = "Invalid session.",
            ["UserNotFoundErrorMessage"] = "User does not exist.",
            ["InvalidOrExpiredTokenErrorMessage"] = "Invalid or expired password reset token.",
            ["CurrentPasswordErrorMessage"] = "Current password is incorrect.",
            ["SamePasswordErrorMessage"] = "New password cannot be the same as the current password.",
            ["UserRolesNotFoundErrorMessage"] = "No roles found for the user.",
            ["RoleExistsErrorMessage"] = "Role already exists for the user.",
            ["AdminCanAssignRoleErrorMessage"] = "Only admins can assign roles.",
            ["AdminCanRemoveRoleErrorMessage"] = "Only admins can remove roles.",
            ["AdminCannotRemoveOwnRoleErrorMessage"] = "Admin cannot remove their own role.",
            ["FailedToSendEmailErrorMessage"] = "Failed to send email.",
            ["FailedToSendVerificationCode"] = "Failed to send verification code.",
            ["NotAdminToFetchSessionErrorMessage"] = "User Not a Admin. Only Admin Users can fetch Session details.",
            ["NoUsersLoggedInErrorMessage"] = "No Users are currently Logged In.",
            ["AdminUserNotFoundErrorMessage"] = "Admin User does not exist.",
            ["NotAnAdminErrorMessage"] = "Not an Admin User.",
            ["UserNotLockedOutErrorMessage"] = "User is not locked out.",
            ["MissingApiKeyErrorMessage"] = "Api Key is Missing.",
            ["InvalidApiKeyErrorMessage"] = "Api Key is Invalid.",
            ["TokenExpiredErrorMessage"] = "Token is Expired.",
            ["InvalidTokenErrorMessage"] = "Token is Invalid.",
        };

        /// <summary>
        /// Gets an error message by its code
        /// </summary>
        /// <param name="errorCode">The error code</param>
        /// <returns>The corresponding error message, or a default message if not found</returns>
        public static string GetErrorMessage(string errorCode)
        {
            if (ErrorMessages.TryGetValue(errorCode, out string message))
            {
                return message;
            }

            return "An unknown error occurred.";
        }

        /// <summary>
        /// Adds or updates an error message
        /// </summary>
        /// <param name="errorCode">The error code</param>
        /// <param name="errorMessage">The error message</param>
        public static void SetErrorMessage(string errorCode, string errorMessage)
        {
            ErrorMessages[errorCode] = errorMessage;
        }

        /// <summary>
        /// Checks if an error code exists
        /// </summary>
        /// <param name="errorCode">The error code to check</param>
        /// <returns>True if the error code exists, false otherwise</returns>
        public static bool HasErrorCode(string errorCode)
        {
            return ErrorMessages.ContainsKey(errorCode);
        }
    }
}
