using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Helpers;

namespace SportifyX.API.Controllers
{
    /// <summary>
    /// ProductsController
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController(IProductService productService, IExceptionHandlingService exceptionHandlingService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The product service
        /// </summary>
        private readonly IProductService _productService = productService;

        /// <summary>
        /// The exception handling service
        /// </summary>
        private readonly IExceptionHandlingService _exceptionHandlingService = exceptionHandlingService;

        #endregion

        #region Methods

        /// <summary>
        /// Adds a new product.
        /// </summary>
        [HttpPost("add")]
        public async Task<IActionResult> AddProduct([FromBody] Products product)
        {
            try
            {
                var response = await _productService.AddProductAsync(product);
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        /// <summary>
        /// Updates an existing product.
        /// </summary>
        [HttpPut("{id:long}/update")]
        public async Task<IActionResult> UpdateProduct(long id, [FromBody] Products product)
        {
            try
            {
                var response = await _productService.UpdateProductAsync(id, product);
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        /// <summary>
        /// Deletes a product.
        /// </summary>
        [HttpDelete("{id:long}/delete")]
        public async Task<IActionResult> DeleteProduct(long id)
        {
            try
            {
                var response = await _productService.DeleteProductAsync(id);
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        /// <summary>
        /// Gets all products.
        /// </summary>
        [HttpGet("get-all")]
        public async Task<IActionResult> GetAllProducts()
        {
            try
            {
                var response = await _productService.GetAllProductsAsync();
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<List<Products>>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        /// <summary>
        /// Gets a product by ID.
        /// </summary>
        [HttpGet("{id:long}")]
        public async Task<IActionResult> GetProductById(long id)
        {
            try
            {
                var response = await _productService.GetProductByIdAsync(id);
                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);
                var errorResponse = ApiResponse<Products>.Fail(StatusCodes.Status500InternalServerError, ErrorMessageHelper.GetErrorMessage("GeneralErrorMessage"));
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion
    }
}
