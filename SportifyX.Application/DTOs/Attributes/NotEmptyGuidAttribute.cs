using System.ComponentModel.DataAnnotations;

namespace SportifyX.Application.DTOs.Attributes
{
    public class NotEmptyGuidAttribute : ValidationAttribute
    {
        public override bool IsValid(object value)
        {
            if (value is Guid guidValue)
            {
                return guidValue != Guid.Empty;  // Validate that it's not an empty GUID
            }
            return false;
        }
    }
}
