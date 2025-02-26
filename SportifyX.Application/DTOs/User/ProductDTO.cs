﻿namespace SportifyX.Application.DTOs.User
{
    public class ProductDTO
    {
        public long Id { get; set; }
        public string? Name { get; set; }
        public string? Description { get; set; }
        public decimal Price { get; set; }
        public int StockQuantity { get; set; }
        public string? Category { get; set; }
    }
}
