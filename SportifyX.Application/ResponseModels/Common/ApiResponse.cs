﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Application.ResponseModels.Common
{
    public class ApiResponse<T>
    {
        /// <summary>
        /// HTTP status code (e.g., 200 for success, 400 for client errors, 500 for server errors).
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// A short message describing the outcome of the request.
        /// </summary>
        public string? Message { get; set; }

        /// <summary>
        /// The data returned by the API. It will be null in case of an error.
        /// </summary>
        public T? Data { get; set; }

        /// <summary>
        /// Optional error details if the request failed.
        /// </summary>
        public List<string>? Errors { get; set; }

        /// <summary>
        /// The timestamp of when the response is created.
        /// </summary>
        public DateTime Timestamp { get; set; }

        public ApiResponse()
        {
            Timestamp = DateTime.UtcNow;
        }

        public ApiResponse(int statusCode, string message, T? data = default, List<string?>? errors = null)
        {
            StatusCode = statusCode;
            Message = message;
            Data = data;
            Errors = errors ?? [];
            Timestamp = DateTime.UtcNow;
        }

        public static ApiResponse<T> Success(T data, string message = "Success")
        {
            return new ApiResponse<T>(200, message, data);
        }

        public static ApiResponse<T> Fail(int statusCode, string message, List<string>? errors = null)
        {
            return new ApiResponse<T>(statusCode, message, default, errors);
        }
    }
}