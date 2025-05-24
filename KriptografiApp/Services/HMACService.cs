using System.Security.Cryptography;

namespace KriptografiApp.Services
{
  public class HMACService
  {
    // veri bütünlüğünün sağlanıp sağlanamadığını kontrol etmek için HMAC algoritmasını kullanır.
    // Immutable değerler için tavsiye ederiz.

    // dışraıdan gönderilen bir değer ile HMAC algoritması kullanarak bir imza oluşturur. 256 bit
    public string SignData(string data, byte[] key)
    {
      using (var hmac = new HMACSHA256(key))
      {
        var dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        var hashBytes = hmac.ComputeHash(dataBytes);
        return Convert.ToBase64String(hashBytes);
      }
    }

    // imzalanmış bir verinin doğruluğunu kontrol eder. 256 bit
    public bool VerifySignature(string data, string base64Signature, byte[] key)
    {
      using (var hmac = new HMACSHA256(key))
      {
        var dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        var hashBytes = hmac.ComputeHash(dataBytes);
        var computedSignature = Convert.ToBase64String(hashBytes);
        return computedSignature == base64Signature;
      }
    }

  }
}
