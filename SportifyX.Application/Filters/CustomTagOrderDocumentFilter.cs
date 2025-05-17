using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SportifyX.Application.Filters
{
    public class CustomTagOrderDocumentFilter : IDocumentFilter
    {
        public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context)
        {
            // Define your custom order here
            var customOrder = new List<string>
            {
                "Auth", "User", "Security", "Products", "Category", "Wishlist", "Cart"
            };

            // If there are no tags, add them manually
            if (swaggerDoc.Tags == null || !swaggerDoc.Tags.Any())
            {
                swaggerDoc.Tags = customOrder
                    .Select(tagName => new OpenApiTag { Name = tagName, Description = $"{tagName} endpoints" })
                    .ToList();
                return;
            }

            // Otherwise, sort existing tags
            swaggerDoc.Tags = swaggerDoc.Tags
                .OrderBy(tag =>
                {
                    var index = customOrder.IndexOf(tag.Name);
                    return index == -1 ? int.MaxValue : index;
                })
                .ThenBy(tag => tag.Name)
                .ToList();
        }
    }
}