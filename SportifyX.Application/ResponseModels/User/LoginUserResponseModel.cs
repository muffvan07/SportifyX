using SportifyX.Domain.Entities;

namespace SportifyX.Application.ResponseModels.User
{
    public class LoginUserResponseModel
    {
        public required string Token { get; set; }
        public long UserId { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public DateTime TokenExpiryDate { get; set; }
    }
}
