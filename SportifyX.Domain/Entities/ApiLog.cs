using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    public class ApiLog
    {
        [Key]
        public long Id { get; set; }
        public string? RequestPath { get; set; }
        public string? HttpMethod { get; set; }
        public string? RequestHeaders { get; set; }
        public string? QueryParams { get; set; }
        public string? RequestBody { get; set; }
        public string? ResponseHeaders { get; set; }
        public string? ResponseBody { get; set; }
        public int StatusCode { get; set; }
        public string? ClientIp { get; set; }
        public long UserId { get; set; }
        public long ExecutionTimeMs { get; set; }
        public DateTime CreationDate { get; set; }
    }
}
