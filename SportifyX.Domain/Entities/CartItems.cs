using SportifyX.Domain.Entities.BaseModel;

namespace SportifyX.Domain.Entities
{
    public class CartItems : BaseObjectModel
    {
        public long Id { get; set; }
        public long UserId { get; set; }
        public long ProductId { get; set; }
        public int Quantity { get; set; }
    }
}
