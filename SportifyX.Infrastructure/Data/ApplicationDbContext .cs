using Microsoft.EntityFrameworkCore;
using SportifyX.Domain.Entities;
using System.Xml;

namespace SportifyX.Infrastructure.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<ApiLog> ApiLogs { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<PasswordRecoveryToken> PasswordRecoveryTokens { get; set; }
        public DbSet<Verifications> Verifications { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UserRole>()
                .HasKey(e => new { e.UserId, e.RoleId });

            modelBuilder.Entity<User>()
                .HasMany(x => x.UserRole)       // Assuming User has a collection of UserRole
                .WithOne(y => y.User)            // Each UserRole is associated with one User
                .HasForeignKey(y => y.UserId);   // Define the foreign key in UserRole for User

            modelBuilder.Entity<UserRole>()
                .HasOne(x => x.Role);            // Each UserRole is associated with one Role

            base.OnModelCreating(modelBuilder);
        }
    }
}
