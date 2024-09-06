using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Infrastructure.Security
{
    public static class KeyGenerator
    {
        public static string GenerateSecretKey()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[32]; // 256-bit key
                rng.GetBytes(key);
                return Convert.ToBase64String(key);
            }
        }
    }
}
