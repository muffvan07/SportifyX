namespace SportifyX.Domain.Entities
{
    public class CartItems
    {
        public long Id { get; set; }
        public long UserId { get; set; }
        public long ProductId { get; set; }
        public int Quantity { get; set; }
    }
}
