using System.Security.Cryptography;

namespace KriptografiApp.Services
{
  public class PasswordHasherService
  {
    public string HashPassword(string Password, string SaltBase64)
    {
      // Password ve Salt değerlerini byte dizisine çeviriyoruz.
      var passwordBytes = System.Text.Encoding.UTF8.GetBytes(Password);
      var saltBytes = Convert.FromBase64String(SaltBase64);

      // Hash algoritmasını kullanarak hashliyoruz.
      using (var hmac = new HMACSHA256(saltBytes))
      {
        var hashBytes = hmac.ComputeHash(passwordBytes);
        return Convert.ToBase64String(hashBytes);
      }
    }


    public bool VerifyPassword(string Password,string PasswordHash, string SaltBase64)
    {
      // Password ve Salt değerlerini byte dizisine çeviriyoruz.
      var passwordBytes = System.Text.Encoding.UTF8.GetBytes(Password);
      var saltBytes = Convert.FromBase64String(SaltBase64);

      // Hash algoritmasını kullanarak hashliyoruz.
      using (var hmac = new HMACSHA256(saltBytes))
      {
        var hashBytes = hmac.ComputeHash(passwordBytes);
        var computedHash = Convert.ToBase64String(hashBytes);
        return computedHash == PasswordHash;
      }
    }

  }
}
