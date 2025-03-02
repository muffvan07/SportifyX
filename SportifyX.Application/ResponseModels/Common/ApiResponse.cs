namespace SportifyX.Application.ResponseModels.Common
{
    public class ApiResponse<T>
    {
        /// <summary>
        /// HTTP status code (e.g., 200 for success, 400 for client errors, 500 for server errors).
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// The data returned by the API. It will be null in case of an error.
        /// </summary>
        public T? Data { get; set; }

        /// <summary>
        /// Optional error details if the request failed.
        /// </summary>
        public string? Errors { get; set; }

        /// <summary>
        /// The timestamp of when the response is created.
        /// </summary>
        public DateTime Timestamp { get; set; }

        public ApiResponse()
        {
            Timestamp = DateTime.UtcNow;
        }

        public ApiResponse(int statusCode, T? data = default, string? error = null)
        {
            StatusCode = statusCode;
            Data = data;
            Errors = error;
            Timestamp = DateTime.UtcNow;
        }

        public static ApiResponse<T> Success(T data)
        {
            return new ApiResponse<T>(200, data);
        }

        public static ApiResponse<T> Fail(int statusCode, string? error = null)
        {
            return new ApiResponse<T>(statusCode, default, error);
        }
    }
}
