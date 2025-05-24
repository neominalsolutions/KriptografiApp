using System.Security.Cryptography;

namespace KriptografiApp.Services
{
  public class AESService
  {

    // Shared key ile encrypt ve decrypt işlemlerini yapar.
    // Shared Key sadece Sunucu tabanlı sitemde saklanmalıdır.
    // yani rsadeki gibi bir publickey süreci yoktur.
    public string Encrypt(string plainText, byte[] sharedKey)
    {
      using(var aes = Aes.Create())
      {

       
        aes.Key = sharedKey;
        aes.GenerateIV(); // IV'yi otomatik olarak oluştur
        aes.Padding = PaddingMode.PKCS7; // byte dizisindeki boşlukları padding yapar doldurur.
        var iv = aes.IV; // Initialization Vector (IV) oluşturulur.

        // IV vektörü her şifreleme işleminde farklı olmalıdır. Bu sayede her seferinde farklı bir şifreleme yapılır.
        // Not: Bir encrpypted verinin decrypt edilmesi için IV'ye ihtiyaç vardır.
        // IV vektör değeri şifrlenmiş verinin içerisinde bir başlangıç değeri olarak bulunur.

        using (var encryptor = aes.CreateEncryptor(aes.Key, iv))
        {
          using (var ms = new MemoryStream())
          {
            ms.Write(iv, 0, iv.Length); // IV'yi başa ekle
            // Şifreli bir stream akışı oluşturmamızı sağlar.
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
              using (var sw = new StreamWriter(cs))
              {
                sw.Write(plainText);
              }
            }
            return Convert.ToBase64String(ms.ToArray());
          }
        }
      }
    }

    public string Decrypt(string cipherText, byte[] sharedKey) {

      var fullCipherBytes = Convert.FromBase64String(cipherText);

      using (var aes = Aes.Create())
      {
        aes.Key = sharedKey;
        aes.Padding = PaddingMode.PKCS7;
        var iv = new byte[aes.IV.Length];


        Array.Copy(fullCipherBytes, iv, iv.Length); // Based64 içerisinde IV vektör değerini aes IV kopyaladık.
        aes.IV = iv;                                          


        using (var decyptor = aes.CreateDecryptor(aes.Key,aes.IV))
        {
          using (var memoryStream = new MemoryStream(fullCipherBytes,iv.Length,fullCipherBytes.Length - iv.Length))
          {
            // memory streamdeki değeri cypto stream üzerinden okuma işlemi
            using (var cs = new CryptoStream(memoryStream,decyptor,CryptoStreamMode.Read))
            {
              using (var sr = new StreamReader(cs))
              {
                return sr.ReadToEnd();
              }
            }
          }

        }

      }

    }
  }
}
