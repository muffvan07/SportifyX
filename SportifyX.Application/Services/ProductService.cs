using SportifyX.Application.Interfaces;
using SportifyX.Domain.Entities;
using SportifyX.Domain.Interfaces;

namespace SportifyX.Application.Services
{
    public class ProductService(IGenericRepository<Product> productRepository) : IProductService
    {
        private readonly IGenericRepository<Product> _productRepository = productRepository;

        public async Task<IEnumerable<Product>> GetAllProductsAsync()
        {
            return await _productRepository.GetAllAsync();
        }

        public async Task<Product> GetProductByIdAsync(Guid id)
        {
            return await _productRepository.GetByIdAsync(id);
        }

        public async Task AddProductAsync(Product product)
        {
            await _productRepository.AddAsync(product);
        }

        public async Task UpdateProductAsync(Product product)
        {
            await _productRepository.UpdateAsync(product);
        }

        public async Task DeleteProductAsync(Guid id)
        {
            await _productRepository.DeleteAsync(x => x.Id.ToString() == "1");
        }
    }
}

