using SportifyX.Application.ResponseModels.Common;
using SportifyX.Domain.Entities;

namespace SportifyX.Application.Services.Interface
{
    public interface ICategoryService
    {
        Task<ApiResponse<bool>> AddCategoryAsync(Categories category);
        Task<ApiResponse<bool>> UpdateCategoryAsync(long id, Categories category);
        Task<ApiResponse<bool>> DeleteCategoryAsync(long id);
        Task<ApiResponse<List<Categories>>> GetAllCategoriesAsync();
    }
}
