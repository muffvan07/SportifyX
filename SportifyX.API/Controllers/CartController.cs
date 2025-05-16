using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;

namespace SportifyX.API.Controllers
{
    /// <summary>
    /// CartController
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class CartController(ICartService cartService, IExceptionHandlingService exceptionHandlingService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The cart service
        /// </summary>
        private readonly ICartService _cartService = cartService;

        /// <summary>
        /// The exception handling service
        /// </summary>
        private readonly IExceptionHandlingService _exceptionHandlingService = exceptionHandlingService;

        #endregion

        #region Methods

        /// <summary>
        /// Adds an item to the cart.
        /// </summary>
        [HttpPost("add")]
        public async Task<IActionResult> AddItemToCart([FromBody] CartItems cartItem)
        {
            try
            {
                var response = await _cartService.AddItemToCartAsync(cartItem);

                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, "An error occurred while adding item to cart.");
                
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        /// <summary>
        /// Updates the quantity of a cart item.
        /// </summary>
        [HttpPut("{id}/update")]
        public async Task<IActionResult> UpdateCartItem(long id, [FromQuery] int quantity)
        {
            try
            {
                var response = await _cartService.UpdateCartItemAsync(id, quantity);

                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, "An error occurred while updating cart item.");
                
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        /// <summary>
        /// Removes an item from the cart.
        /// </summary>
        [HttpDelete("{id}/delete")]
        public async Task<IActionResult> RemoveItemFromCart(long id)
        {
            try
            {
                var response = await _cartService.RemoveItemFromCartAsync(id);

                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<bool>.Fail(StatusCodes.Status500InternalServerError, "An error occurred while removing item from cart.");
                
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        /// <summary>
        /// Gets all cart items for a user.
        /// </summary>
        [HttpGet("{userId}/items")]
        public async Task<IActionResult> GetCartItems(long userId)
        {
            try
            {
                var response = await _cartService.GetCartItemsByUserIdAsync(userId);

                return response.StatusCode == StatusCodes.Status200OK ? Ok(response) : StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                await _exceptionHandlingService.LogExceptionAsync(ex, HttpContext);

                var errorResponse = ApiResponse<List<CartItems>>.Fail(StatusCodes.Status500InternalServerError, "An error occurred while retrieving cart items.");
                
                return StatusCode(StatusCodes.Status500InternalServerError, errorResponse);
            }
        }

        #endregion
    }
}
