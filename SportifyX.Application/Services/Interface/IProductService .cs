using SportifyX.Application.ResponseModels.Common;
using SportifyX.Domain.Entities;

namespace SportifyX.Application.Services.Interface
{
    public interface IProductService
    {
        Task<ApiResponse<bool>> AddProductAsync(Products product);
        Task<ApiResponse<bool>> UpdateProductAsync(Guid id, Products product);
        Task<ApiResponse<bool>> DeleteProductAsync(Guid id);
    }
}
