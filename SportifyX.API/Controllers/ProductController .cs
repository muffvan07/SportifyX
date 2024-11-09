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
        public async Task<IActionResult> UpdateProduct(Guid id, Products product)
        {
            return Ok(await _productService.UpdateProductAsync(id, product));
        }

        [HttpDelete("{id}/delete")]
        public async Task<IActionResult> DeleteProduct(Guid id)
        {
            return Ok(await _productService.DeleteProductAsync(id));
        }
    }
}
