using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;

namespace SportifyX.API.Controllers
{
    [Route("api/cart")]
    [ApiController]
    public class CartController(ICartService cartService) : ControllerBase
    {
        private readonly ICartService _cartService = cartService;

        [HttpPost("add")]
        public async Task<IActionResult> AddItemToCart(CartItems cartItem) =>
            Ok(await _cartService.AddItemToCartAsync(cartItem));

        [HttpPut("{id}/update")]
        public async Task<IActionResult> UpdateCartItem(Guid id, int quantity) =>
            Ok(await _cartService.UpdateCartItemAsync(id, quantity));

        [HttpDelete("{id}/delete")]
        public async Task<IActionResult> RemoveItemFromCart(Guid id) =>
            Ok(await _cartService.RemoveItemFromCartAsync(id));
    }
}
