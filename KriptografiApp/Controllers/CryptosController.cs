using KriptografiApp.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace KriptografiApp.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class CryptosController : ControllerBase
  {
    private readonly RSAService _rSAService;


    public CryptosController(RSAService rSAService)
    {
      _rSAService = rSAService;
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
  }
}
