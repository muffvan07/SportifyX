using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Domain.Entities
{
    public class ApiLog
    {
        public int Id { get; set; }
        public string? HttpMethod { get; set; }
        public string? Endpoint { get; set; }
        public string? RequestBody { get; set; }
        public string? ResponseBody { get; set; }
        public long ResponseTime { get; set; } // In milliseconds
        public string? CreatedBy { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
