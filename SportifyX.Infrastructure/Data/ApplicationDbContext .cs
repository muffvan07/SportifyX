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
        //public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<PasswordRecoveryToken> PasswordRecoveryTokens { get; set; }
        public DbSet<Verification> Verifications { get; set; }
        public DbSet<ExceptionLog> ExceptionLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Define composite primary key for UserRole
            modelBuilder.Entity<UserRole>()
                .HasKey(ur => new { ur.Id });

            // Define relationship: User -> UserRole
            modelBuilder.Entity<User>()
                .HasMany(u => u.UserRole)     // User has many UserRoles
                .WithOne(ur => ur.User)        // Each UserRole has one User
                .HasForeignKey(ur => ur.UserId); // Delete UserRoles when User is deleted

            // Define relationship: Role -> UserRole
            //modelBuilder.Entity<Role>()
            //    .HasMany(r => r.UserRole)     // Role has many UserRoles
            //    .WithOne(ur => ur.Role)        // Each UserRole has one Role
            //    .HasForeignKey(ur => ur.RoleId) // Foreign key in UserRole
            //    .OnDelete(DeleteBehavior.Restrict); // Prevent role deletion if assigned

            base.OnModelCreating(modelBuilder);
        }
    }
}
