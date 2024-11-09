using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    /// <summary>
    /// CartService
    /// </summary>
    /// <seealso cref="SportifyX.Application.Services.Interface.ICartService" />
    public class CartService(IGenericRepository<CartItems> cartRepository) : ICartService
    {
        #region Variables

        /// <summary>
        /// The cart repository
        /// </summary>
        private readonly IGenericRepository<CartItems> _cartRepository = cartRepository;

        #endregion

        #region Action Methods

        /// <summary>
        /// Adds the item to cart asynchronous.
        /// </summary>
        /// <param name="cartItem">The cart item.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> AddItemToCartAsync(CartItems cartItem)
        {
            await _cartRepository.AddAsync(cartItem);
            return ApiResponse<bool>.Success(true);
        }

        /// <summary>
        /// Updates the cart item asynchronous.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <param name="quantity">The quantity.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> UpdateCartItemAsync(Guid id, int quantity)
        {
            var cartItem = await _cartRepository.GetByIdAsync(id);
            if (cartItem == null)
                return ApiResponse<bool>.Fail(404, "Not Found", new List<string> { "Cart item not found." });

            cartItem.Quantity = quantity;
            await _cartRepository.UpdateAsync(cartItem);

            return ApiResponse<bool>.Success(true);
        }

        /// <summary>
        /// Removes the item from cart asynchronous.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> RemoveItemFromCartAsync(Guid id)
        {
            await _cartRepository.DeleteAsync(x => x.Id == id);
            return ApiResponse<bool>.Success(true);
        }

        #endregion
    }
}
