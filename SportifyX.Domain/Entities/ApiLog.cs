using System.ComponentModel.DataAnnotations;

namespace SportifyX.Domain.Entities
{
    /// <summary>
    /// Represents a detailed log entry for API requests and responses.
    /// </summary>
    public class ApiLog
    {
        [Key]
        public long Id { get; set; }

        /// <summary>
        /// The full request URL path.
        /// </summary>
        public string? RequestPath { get; set; }

        /// <summary>
        /// The HTTP method (GET, POST, etc.).
        /// </summary>
        public string? HttpMethod { get; set; }

        /// <summary>
        /// Serialized request headers.
        /// </summary>
        public string? RequestHeaders { get; set; }

        /// <summary>
        /// Serialized query parameters.
        /// </summary>
        public string? QueryParams { get; set; }

        /// <summary>
        /// Serialized request body.
        /// </summary>
        public string? RequestBody { get; set; }

        /// <summary>
        /// Serialized response headers.
        /// </summary>
        public string? ResponseHeaders { get; set; }

        /// <summary>
        /// Serialized response body.
        /// </summary>
        public string? ResponseBody { get; set; }

        /// <summary>
        /// HTTP status code of the response.
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// Client IP address.
        /// </summary>
        public string? ClientIp { get; set; }

        /// <summary>
        /// User ID associated with the request.
        /// </summary>
        public long UserId { get; set; }

        /// <summary>
        /// Time taken to execute the request, in milliseconds.
        /// </summary>
        public long ExecutionTimeMs { get; set; }

        /// <summary>
        /// Date and time when the log entry was created (UTC).
        /// </summary>
        public DateTime CreationDate { get; set; }

        // Enhanced fields for advanced diagnostics and tracing

        /// <summary>
        /// Correlation ID for distributed tracing.
        /// </summary>
        [MaxLength(100)]
        public string? CorrelationId { get; set; }

        /// <summary>
        /// Content-Type of the request.
        /// </summary>
        [MaxLength(200)]
        public string? RequestContentType { get; set; }

        /// <summary>
        /// Content-Length of the request.
        /// </summary>
        public long? RequestContentLength { get; set; }

        /// <summary>
        /// Content-Type of the response.
        /// </summary>
        [MaxLength(200)]
        public string? ResponseContentType { get; set; }

        /// <summary>
        /// Content-Length of the response.
        /// </summary>
        public long? ResponseContentLength { get; set; }

        /// <summary>
        /// User-Agent header value.
        /// </summary>
        [MaxLength(500)]
        public string? UserAgent { get; set; }

        /// <summary>
        /// Referer header value.
        /// </summary>
        [MaxLength(500)]
        public string? Referer { get; set; }

        /// <summary>
        /// HTTP protocol version.
        /// </summary>
        [MaxLength(50)]
        public string? Protocol { get; set; }

        /// <summary>
        /// UTC timestamp when the request started.
        /// </summary>
        public DateTime? RequestStartTime { get; set; }

        /// <summary>
        /// UTC timestamp when the request ended.
        /// </summary>
        public DateTime? RequestEndTime { get; set; }

        /// <summary>
        /// Exception details if an error occurred.
        /// </summary>
        public string? Exception { get; set; }
    }
}
