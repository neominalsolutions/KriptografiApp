using System.Security.Cryptography;
using System.Text;

namespace KriptografiApp.Services
{
  public class RSAService
  {
    private readonly RSA _privateRsa;
    private readonly RSA _publicRsa;


        public RSAService()
        {
            _privateRsa = RSA.Create();
            _publicRsa = RSA.Create();
      // Load the keys from files
          var privateKey = File.ReadAllText("RsaKeys/private_key.pem");
          _privateRsa.ImportFromPem(privateKey.ToCharArray());
        }

    // encrypt işlemi için public key kullanıyoruz
    public string Encrypt(string plainText, string publicKeyBase64)
    {
      byte[] bytes = Convert.FromBase64String(publicKeyBase64);
      // hangi public key ile encrypt edildiğini anlamak için public key ile decrypt etmeye çalışıyoruz
      _publicRsa.ImportSubjectPublicKeyInfo(bytes, out _);

      var data = System.Text.Encoding.UTF8.GetBytes(plainText);
      var encryptedData = _publicRsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);


      return Convert.ToBase64String(encryptedData);
    }

    // Not: Bu metot sadece private key ile decrypt edilebilir. decrypt işlemleri için private key kullanalım.
    public string Decrypt(string encrypted)
    {

      var data = Convert.FromBase64String(encrypted);
      var encryptedData = _privateRsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);

      return Encoding.UTF8.GetString(encryptedData);
    }

  }


}
