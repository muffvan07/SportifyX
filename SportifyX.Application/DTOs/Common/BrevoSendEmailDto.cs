namespace SportifyX.Application.DTOs.Common
{
    public class BrevoSendEmailDto
    {
        public class EmailPayload
        {
            public UserInfo? Sender { get; set; }
            public List<UserInfo> To { get; set; } = null!;
            public List<UserInfo> Cc { get; set; } = null!;
            public List<UserInfo> Bcc { get; set; } = null!;
            public string HtmlContent { get; set; } = null!;
            public string Subject { get; set; } = null!;
            public UserInfo? ReplyTo { get; set; } = null!;
            public List<string>? Tags { get; set; } = null!;
        }

        public class UserInfo
        {
            public string Name { get; set; } = null!;
            public string Email { get; set; } = null!;
        }
    }
}
