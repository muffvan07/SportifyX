namespace SportifyX.Application.ResponseModels.User
{
    public class LoggedInUsersResponseModel
    {
        public long Id { get; set; }
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; }
        public DateTime DOB { get; set; }
        public int Gender { get; set; }
        public bool IsPhoneNumberConfirmed { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public DateTime? SessionExipry { get; set; }
        public string? UserRoles { get; set; }
    }
}
