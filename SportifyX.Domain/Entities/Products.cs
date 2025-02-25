namespace SportifyX.Domain.Entities
{
    public class Products
    {
        public long Id { get; set; }
        public long CategoryId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Brand { get; set; } = string.Empty;
        public string Gender { get; set; } = string.Empty;
        public decimal Price { get; set; }
        public string Material { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }
}
