using SportifyX.Application.ResponseModels.Common;
using SportifyX.Domain.Entities;

namespace SportifyX.Application.Services.Interface
{
    public interface IProductService
    {
        Task<ApiResponse<bool>> AddProductAsync(Products product);
        Task<ApiResponse<bool>> UpdateProductAsync(long id, Products product);
        Task<ApiResponse<bool>> DeleteProductAsync(long id);
        Task<ApiResponse<List<Products>>> GetAllProductsAsync();
        Task<ApiResponse<Products>> GetProductByIdAsync(long id);
    }
}
