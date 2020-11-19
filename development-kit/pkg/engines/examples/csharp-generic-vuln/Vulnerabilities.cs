using System;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace NetCoreVulnerabilities
{
    public class NetCoreVulnerabilities : ControllerBase
    {
        public void WeakHashingFunction()
        {
            var str = new byte[] { };
            var hashProvider = new SHA1CryptoServiceProvider();
            var hash = hashProvider.ComputeHash(str);
        }

        public void HardcodedPassword()
        {
            var client = new SmtpClient();
            client.Credentials = new NetworkCredential("test@test.com", "testpassword");
            var mm = new MailMessage("test", "test", "test", "test");
            client.Send(mm);
        }

        public void WeakRandomNumberGenerator()
        {
            var rnd = new Random();
            var buffer = new byte[16];
            rnd.NextBytes(buffer);
            BitConverter.ToString(buffer);
        }

        public void CookieWithoutHttpOnlyFlag()
        {
            var cookie = new CookieOptions();
            cookie.Secure = false;
        }
        
        [HttpGet()]
        public string CrossSiteScripting(string myParam)
        {
            return "value " + myParam;
        }
    }
}