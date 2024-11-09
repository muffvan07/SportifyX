using SportifyX.Application.ResponseModels.Common;
using SportifyX.Domain.Entities;

namespace SportifyX.Application.Services.Interface
{
    public interface ICartService
    {
        Task<ApiResponse<bool>> AddItemToCartAsync(CartItems cartItem);
        Task<ApiResponse<bool>> UpdateCartItemAsync(Guid id, int quantity);
        Task<ApiResponse<bool>> RemoveItemFromCartAsync(Guid id);
    }
}
