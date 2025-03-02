using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    /// <summary>
    /// CategoryService
    /// </summary>
    /// <seealso cref="SportifyX.Application.Services.Interface.ICategoryService" />
    public class CategoryService(IGenericRepository<Categories> categoryRepository) : ICategoryService
    {
        #region Variables

        /// <summary>
        /// The category repository
        /// </summary>
        private readonly IGenericRepository<Categories> _categoryRepository = categoryRepository;

        #endregion

        #region Action Methods

        /// <summary>
        /// Adds the category asynchronous.
        /// </summary>
        /// <param name="category">The category.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> AddCategoryAsync(Categories category)
        {
            await _categoryRepository.AddAsync(category);
            return ApiResponse<bool>.Success(true);
        }

        /// <summary>
        /// Updates the category asynchronous.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <param name="category">The category.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> UpdateCategoryAsync(long id, Categories category)
        {
            var existingCategory = await _categoryRepository.GetByIdAsync(id);
            if (existingCategory == null)
                return ApiResponse<bool>.Fail(404, "Category not found.");

            existingCategory.Name = category.Name;
            existingCategory.Description = category.Description;
            await _categoryRepository.UpdateAsync(existingCategory);

            return ApiResponse<bool>.Success(true);
        }

        /// <summary>
        /// Deletes the category asynchronous.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> DeleteCategoryAsync(long id)
        {
            await _categoryRepository.DeleteAsync(x => x.Id == id);
            return ApiResponse<bool>.Success(true);
        }

        public async Task<ApiResponse<List<Categories>>> GetAllCategoriesAsync()
        {
            var categories = await _categoryRepository.GetAllAsync();
            return ApiResponse<List<Categories>>.Success(categories.ToList());
        }

        #endregion
    }
}
