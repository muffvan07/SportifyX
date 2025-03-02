using SportifyX.Application.ResponseModels.Common;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    /// <summary>
    /// ProductService
    /// </summary>
    /// <seealso cref="SportifyX.Application.Services.Interface.IProductService" />
    public class ProductService(IGenericRepository<Products> productRepository) : IProductService
    {
        #region Variables

        /// <summary>
        /// The product repository
        /// </summary>
        private readonly IGenericRepository<Products> _productRepository = productRepository;

        #endregion

        #region Action Methods

        /// <summary>
        /// Adds the product asynchronous.
        /// </summary>
        /// <param name="product">The product.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> AddProductAsync(Products product)
        {
            await _productRepository.AddAsync(product);
            return ApiResponse<bool>.Success(true);
        }

        /// <summary>
        /// Updates the product asynchronous.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <param name="product">The product.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> UpdateProductAsync(long id, Products product)
        {
            var existingProduct = await _productRepository.GetByIdAsync(id);
            if (existingProduct == null)
                return ApiResponse<bool>.Fail(404, "Product not found.");

            existingProduct.Name = product.Name;
            existingProduct.CategoryId = product.CategoryId;
            existingProduct.Brand = product.Brand;
            existingProduct.Gender = product.Gender;
            existingProduct.Price = product.Price;
            existingProduct.Material = product.Material;
            existingProduct.Description = product.Description;

            await _productRepository.UpdateAsync(existingProduct);

            return ApiResponse<bool>.Success(true);
        }

        /// <summary>
        /// Deletes the product asynchronous.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <returns></returns>
        public async Task<ApiResponse<bool>> DeleteProductAsync(long id)
        {
            await _productRepository.DeleteAsync(x => x.Id == id);
            return ApiResponse<bool>.Success(true);
        }

        public async Task<ApiResponse<List<Products>>> GetAllProductsAsync()
        {
            var products = await _productRepository.GetAllAsync();
            return ApiResponse<List<Products>>.Success(products.ToList());
        }

        public async Task<ApiResponse<Products>> GetProductByIdAsync(long id)
        {
            var product = await _productRepository.GetByIdAsync(id);
            if (product == null)
                return ApiResponse<Products>.Fail(404, "Product not found.");

            return ApiResponse<Products>.Success(product);
        }

        #endregion
    }
}

