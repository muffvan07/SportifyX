﻿using Microsoft.AspNetCore.Mvc;
using SportifyX.Application.Services.Interface;
using SportifyX.Domain.Entities;

namespace SportifyX.API.Controllers
{
    [Route("api/wishlist")]
    [ApiController]
    public class WishlistController(IWishlistService wishlistService) : ControllerBase
    {
        private readonly IWishlistService _wishlistService = wishlistService;

        [HttpPost("add")]
        public async Task<IActionResult> AddItemToWishlist(WishlistItems wishlistItem) =>
            Ok(await _wishlistService.AddItemToWishlistAsync(wishlistItem));

        [HttpDelete("{id}/delete")]
        public async Task<IActionResult> RemoveItemFromWishlist(Guid id) =>
            Ok(await _wishlistService.RemoveItemFromWishlistAsync(id));
    }
}