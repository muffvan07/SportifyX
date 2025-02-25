using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;

namespace SportifyX.API.Controllers
{
    [Route("api/products")]
    [ApiController]
    public class ProductsController(IProductService productService) : ControllerBase
    {
        private readonly IProductService _productService = productService;

        [HttpPost("add")]
        public async Task<IActionResult> AddProduct(Products product)
        {
            return Ok(await _productService.AddProductAsync(product));
        }

        [HttpPut("{id}/update")]
        public async Task<IActionResult> UpdateProduct(long id, Products product)
        {
            return Ok(await _productService.UpdateProductAsync(id, product));
        }

        [HttpDelete("{id}/delete")]
        public async Task<IActionResult> DeleteProduct(long id)
        {
            return Ok(await _productService.DeleteProductAsync(id));
        }

        [HttpGet("get-all")]
        public async Task<IActionResult> GetAllProducts()
        {
            var result = await _productService.GetAllProductsAsync();
            return Ok(result);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetProductById(long id)
        {
            var result = await _productService.GetProductByIdAsync(id);

            return Ok(result);
        }
    }
}
