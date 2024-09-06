namespace SportifyX.Domain.Settings
{
    public class JwtSettings
    {
        public required string SecretKey { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
    }
}
