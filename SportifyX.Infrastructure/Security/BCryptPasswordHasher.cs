using SportifyX.Domain.Interfaces;

namespace SportifyX.Infrastructure.Security
{
    public class BCryptPasswordHasher : IPasswordHasher
    {
        public string HashPassword(string password)
        {
            // Hash the password using BCrypt
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public bool VerifyPassword(string hashedPassword, string password)
        {
            // Verify the password using BCrypt
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }
    }
}
