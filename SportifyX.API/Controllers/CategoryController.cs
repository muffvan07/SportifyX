using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;

namespace SportifyX.API.Controllers
{
    /// <summary>
    /// CategoryController
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Mvc.ControllerBase" />
    [Route("api/category")]
    [ApiController]
    public class CategoryController(ICategoryService categoryService) : ControllerBase
    {
        #region Variables

        /// <summary>
        /// The category service
        /// </summary>
        private readonly ICategoryService _categoryService = categoryService;

        #endregion

        #region Methods

        [HttpPost("add")]
        public async Task<IActionResult> AddCategory(Categories category)
        {
            return Ok(await _categoryService.AddCategoryAsync(category));
        }

        [HttpPut("{id}/update")]
        public async Task<IActionResult> UpdateCategory(long id, Categories category)
        {
            return Ok(await _categoryService.UpdateCategoryAsync(id, category));
        }

        [HttpDelete("{id}/delete")]
        public async Task<IActionResult> DeleteCategory(long id)
        {
            return Ok(await _categoryService.DeleteCategoryAsync(id));
        }

        [HttpGet("get-all")]
        public async Task<IActionResult> GetAllCategories()
        {
            var result = await _categoryService.GetAllCategoriesAsync();
            return Ok(result);
        }

        #endregion
    }
}
