namespace SportifyX.Domain.Entities.BaseModel
{
    public class BaseObjectModel
    {
        public DateTime CreationDate { get; set; }
        public string CreatedBy { get; set; } = string.Empty;
        public DateTime? ModificationDate { get; set; }
        public string? ModifiedBy { get; set; } = null;
    }
}
