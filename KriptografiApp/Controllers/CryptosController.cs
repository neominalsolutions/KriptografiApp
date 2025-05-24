using KriptografiApp.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace KriptografiApp.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class CryptosController : ControllerBase
  {
    private readonly RSAService _rSAService;
    private readonly HMACService _hMACService;
    private readonly PasswordHasherService _passwordHasherService;
    private readonly AESService _aESService;


    public CryptosController(RSAService rSAService, HMACService hMACService, PasswordHasherService passwordHasherService, AESService aESService)
    {
      _rSAService = rSAService;
      _hMACService = hMACService;
      _passwordHasherService = passwordHasherService;
      _aESService = aESService;
    }

    // Public Key Base64 göndermek
    [HttpGet("publicKey")]
    public IActionResult GetPublicKey()
    {
      var publicKey = System.IO.File.ReadAllText("RsaKeys/public_key1.pem");

      // Temizleme işlemini Pem dosyasını Base64 çeviridğimizden yaptık.
      string base64PublicKey = publicKey.Replace("\n", "").Replace("\r","").Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Trim();

      var keyBytesBase64 = Convert.FromBase64String(base64PublicKey);


      return Ok(new { keyBytesBase64 });
    }


    [HttpPost("rsaDecrypt")]
    public IActionResult RsaDecrypt(string ciperText)
    {
      var data =  _rSAService.Decrypt(ciperText);

      return Ok(new { data });
    }


    [HttpPost("rsaEncrpt")]
    public IActionResult RsaEncrpt(string plainText, string publicKeyBase64)
    {
      var response = _rSAService.Encrypt(plainText, publicKeyBase64);


      return Ok(new {response});
    }


    [HttpPost("hmacSign")]  
    public IActionResult SignData(string text)
    {
      var HcMackey = "ab012345678910234567896123547859631"; // 32 byte 256 bit 
      var keyBytes= Encoding.UTF8.GetBytes(HcMackey);

      var dataBase64 = _hMACService.SignData(text, keyBytes);

      return Ok(new { dataBase64 });
    }


    [HttpPost("hmacVerify")]
    public IActionResult VerifySign(string text, string signatureBase64)
    {
      var HcMackey = "ab012345678910234567896123547859631"; // 32 byte 256 bit 
      var keyBytes = Encoding.UTF8.GetBytes(HcMackey);

      var result =  _hMACService.VerifySignature(text, signatureBase64, keyBytes);

      return Ok(result);
    }

    // RainBow Table
    // Admin1  ab012345678910234567896123547859631 No SALT 8787887787878 ab01234567891023456789612
    // Password1  ab0123456789102345678961235478596781 No SALT

    // Dictionary Attack -> Login ekranlarına deneme yapmak
    // CAPTCHA, 5 kere yanlış deneme olursa Account Lock mekanizması 


    [HttpPost("hashPassword")]
    public IActionResult HashPassword(string password)
    {
    
      // Random 32 byte 256 bit bir key oluşturduk. 
      var keyBytes = new byte[32];
      RandomNumberGenerator.Create().GetBytes(keyBytes);

      // Her seferinde aynı parola için farklı hash değeri üretecek. 

      var passwordSalt =  Convert.ToBase64String(keyBytes);
      var dataBase64 = _passwordHasherService.HashPassword(password, passwordSalt);

      return Ok(new { dataBase64 });
    }

    [HttpPost("verifyPassword")]
    public IActionResult VerifyPassword(string password,string passwordHash)
    {

      var passwordSalt = "MaBHT7OdW3RHZE1ZJ5SftrcWHPJlt4DqfKGbrjJIpD8="; // 32 byte 256 bit

      var result = _passwordHasherService.VerifyPassword(password, passwordHash, passwordSalt);

      return Ok(new { result });
    }


    [HttpPost("aesEncrypt")]
    public IActionResult AesEncrypt(string plainText)
    {


      string sharedKey = "ab012345678910234567896123547859"; // 32 byte 256 bit
      byte[] keyBytes = Encoding.UTF8.GetBytes(sharedKey);



      var response = _aESService.Encrypt(plainText, keyBytes);


      return Ok(new { response });
    }


    [HttpPost("aesDecrypt")]
    public IActionResult AesDecrypt(string cipherText)
    {


      string sharedKey = "ab012345678910234567896123547859"; // 32 byte 256 bit
      byte[] keyBytes = Encoding.UTF8.GetBytes(sharedKey);



      var response = _aESService.Decrypt(cipherText, keyBytes);


      return Ok(new { response });
    }






  }
}
