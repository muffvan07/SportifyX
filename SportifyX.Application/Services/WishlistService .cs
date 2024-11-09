using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    /// <summary>
    /// WishlistService
    /// </summary>
    /// <seealso cref="SportifyX.Application.Services.Interface.IWishlistService" />
    public class WishlistService(IGenericRepository<WishlistItems> wishlistRepository) : IWishlistService
    {
        #region Variables

        /// <summary>
        /// The wishlist repository
        /// </summary>
        private readonly IGenericRepository<WishlistItems> _wishlistRepository = wishlistRepository;

        #endregion

        #region Action Methods

        /// <summary>
        /// Adds the item to wishlist asynchronous.
        /// </summary>
        /// <param name="wishlistItem">The wishlist item.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> AddItemToWishlistAsync(WishlistItems wishlistItem)
        {
            await _wishlistRepository.AddAsync(wishlistItem);
            return ApiResponse<bool>.Success(true);
        }

        /// <summary>
        /// Removes the item from wishlist asynchronous.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> RemoveItemFromWishlistAsync(Guid id)
        {
            await _wishlistRepository.DeleteAsync(x => x.Id == id);
            return ApiResponse<bool>.Success(true);
        }

        #endregion
    }
}
