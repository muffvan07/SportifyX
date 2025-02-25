using SportifyX.Application.ResponseModels.Common;
using SportifyX.Domain.Entities;

namespace SportifyX.Application.Services.Interface
{
    public interface IWishlistService
    {
        Task<ApiResponse<bool>> AddItemToWishlistAsync(WishlistItems wishlistItem);
        Task<ApiResponse<bool>> RemoveItemFromWishlistAsync(long id);
        Task<ApiResponse<List<WishlistItems>>> GetWishlistItemsByUserIdAsync(long userId);
    }
}
