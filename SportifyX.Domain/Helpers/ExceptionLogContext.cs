namespace SportifyX.Domain.Helpers
{
    public class ExceptionLogContext
    {
        public string? UserId { get; set; }
        public string? UserName { get; set; }
        public string? RequestPath { get; set; }
        public string? RequestMethod { get; set; }
        public string? QueryString { get; set; }
        public string? RequestBody { get; set; }
        public string? ClientIp { get; set; }
        public Dictionary<string, object>? AdditionalInfo { get; set; }
    }
}
