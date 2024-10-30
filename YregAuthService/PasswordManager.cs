using System.Security.Cryptography;
using System.Text;

namespace YregAuthService
{
    public class PasswordManager
    {
        private static byte[] Hash(string value, byte[] salt)
        {
            return Hash(Encoding.UTF8.GetBytes(value), salt);
        }
        private static byte[] Hash(byte[] value, byte[] salt)
        {
            byte[] saltedValue = value.Concat(salt).ToArray();
            byte[] hash;
            using (var algorithm = SHA256.Create())
            {
                hash = algorithm.ComputeHash(saltedValue);
            }
            return hash;
        }
        private static int defaultSaltLength = 32;
        private static byte[] GetSalt()
        {
            return GetSalt(defaultSaltLength);
        }
        private static byte[] GetSalt(int saltLength)
        {
            var salt = new byte[saltLength];
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetNonZeroBytes(salt);
            }
            return salt;
        }
        public static string ToHexString(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var t in bytes)
            {
                sb.Append(t.ToString("X2"));
            }
            return sb.ToString();
        }
        public static byte[] FromHexString(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        public static string EncryptPassword(string password)
        {
            var salt = GetSalt();
            return EncryptPassword(password, salt);
        }

        public static string EncryptPassword(string password, byte[] salt)
        {
            var hash = Hash(password, salt);
            return ToHexString(salt) + "$" + ToHexString(hash);
        }
        public static bool VerifyPassword(string? encryptedPassword, string? password)
        {
            if (encryptedPassword == null || password == null)
            {
                return false;
            }
            var parts = encryptedPassword.Split('$');
            if (parts.Length != 2)
            {
                return false;
            }
            var salt = FromHexString(parts[0]);
            return encryptedPassword == EncryptPassword(password, salt);
        }
    }
}
