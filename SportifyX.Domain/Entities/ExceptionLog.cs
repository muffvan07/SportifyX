using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SportifyX.Domain.Entities
{
    [Table("ExceptionLogs")]
    public class ExceptionLog
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public long Id { get; set; }

        [Required]
        [MaxLength(255)]
        public required string ExceptionType { get; set; }

        [Required]
        public required string Message { get; set; }

        public string? StackTrace { get; set; }

        [MaxLength(255)]
        public string? Source { get; set; }

        [MaxLength(255)]
        public string? TargetSite { get; set; }

        [MaxLength(100)]
        public long UserId { get; set; }

        [Required]
        [MaxLength(255)]
        public string? RequestPath { get; set; }

        [MaxLength(10)]
        public string? RequestMethod { get; set; }

        public string? QueryString { get; set; }

        public string? RequestBody { get; set; }

        [MaxLength(50)]
        public string? ClientIp { get; set; }

        [MaxLength(255)]
        public string? MachineName { get; set; }

        [MaxLength(100)]
        public string? AppDomain { get; set; }

        public DateTime CreationDate { get; set; }
    }
}
