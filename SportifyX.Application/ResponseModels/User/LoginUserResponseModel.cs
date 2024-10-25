namespace SportifyX.Application.ResponseModels.User
{
    public class LoginUserResponseModel
    {
        public required string Token { get; set; }
        public Guid UserId { get; set; }
    }
}
