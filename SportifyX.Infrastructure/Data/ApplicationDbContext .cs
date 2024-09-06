using Microsoft.EntityFrameworkCore;
using SportifyX.Domain.Entities;

namespace SportifyX.Infrastructure.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<Product> Products { get; set; }
        public DbSet<User> User { get; set; }
        public DbSet<ApiLog> ApiLog { get; set; }
    }
}
