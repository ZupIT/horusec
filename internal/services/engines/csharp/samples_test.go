// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package csharp

const (
	SampleVulnerableHSCSHARP1 = `
		var p = new Process();
		p.StartInfo.FileName = "exportLegacy.exe";
		p.StartInfo.Arguments = " -user " + input + " -role user";
		p.Start();
	`

	SampleSafeHSCSHARP1 = `
		var p = new Process();
		p.StartInfo.FileName = "exportLegacy.exe";
		p.Start();
	`

	SampleVulnerableHSCSHARP2 = `
		var doc = new XmlDocument {XmlResolver = null};
		doc.Load("/config.xml");
		var results = doc.SelectNodes("/Config/Devices/Device[id='" + input + "']");
	`

	SampleSafeHSCSHARP2 = `
		XmlDocument doc = new XmlDocument { XmlResolver = null };
		doc.Load("/config.xml");
		var results = doc.SelectSingleNode("/Config/Devices/Device");
	`
	SampleVulnerableHSCSHARP3 = `
XmlReaderSettings settings = new XmlReaderSettings();
settings.ProhibitDtd = false;
XmlReader reader = XmlReader.Create(inputXml, settings);
`
	SampleSafeHSCSHARP3 = `
XmlReaderSettings settings = new XmlReaderSettings();
settings.ProhibitDtd = true;
XmlReader reader = XmlReader.Create(inputXml, settings);`
	SampleVulnerableHSCSHARP4 = `
[RedirectingAction]
public ActionResult Download(string fileName)
{
    byte[] fileBytes = System.IO.File.ReadAllBytes(Server.MapPath("~/ClientDocument/") + fileName);
    return File(fileBytes, System.Net.Mime.MediaTypeNames.Application.Octet, fileName);
}
`
	SampleSafeHSCSHARP4 = `
[RedirectingAction]
public ActionResult Download(string fileName)
{
    private static readonly char[] InvalidFilenameChars = Path.GetInvalidFileNameChars();

    if (fileName.IndexOfAny(InvalidFilenameChars) >= 0)
        return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
        
    byte[] fileBytes = System.IO.File.ReadAllBytes(Server.MapPath("~/ClientDocument/") + fileName);
    return File(fileBytes, System.Net.Mime.MediaTypeNames.Application.Octet, fileName);
}
`
	SampleVulnerableHSCSHARP5 = `
var cmd = "SELECT * FROM Users WHERE username = '" + input + "' and role='user'";
ctx.Database.ExecuteSqlCommand(
    cmd);
`
	SampleSafeHSCSHARP5 = `
var cmd = "SELECT * FROM Users WHERE username = @username and role='user'";
ctx.Database.ExecuteSqlCommand(
    cmd,
    new SqlParameter("@username", input));
`
	SampleVulnerableHSCSHARP6 = `
using (var aes = new AesManaged {
    KeySize = KeyBitSize,
    BlockSize = BlockBitSize,
    Mode = CipherMode.OFB,
    Padding = PaddingMode.PKCS7
})
{
    using (var encrypter = aes.CreateEncryptor(cryptKey, new byte[16]))
    using (var cipherStream = new MemoryStream())
    {
        using (var cryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
        using (var binaryWriter = new BinaryWriter(cryptoStream))
        {
            //Encrypt Data
            binaryWriter.Write(secretMessage);
        }
        cipherText = cipherStream.ToArray();
    }
}
//Missing HMAC suffix to assure integrity
`
	SampleSafeHSCSHARP6 = `
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public static readonly int BlockBitSize = 128;
public static readonly int KeyBitSize = 256;

public static byte[] SimpleEncrypt(byte[] secretMessage, byte[] key)
{
    //User Error Checks
    if (key == null || key.Length != KeyBitSize / 8)
        throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "key");

    if (secretMessage == null || secretMessage.Length == 0)
        throw new ArgumentException("Secret Message Required!", "secretMessage");

    //Using random nonce large enough not to repeat
    var nonce = new byte[NonceBitSize / 8];
    Random.NextBytes(nonce, 0, nonce.Length);

    var cipher = new GcmBlockCipher(new AesFastEngine());
    var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, new byte[0]);
    cipher.Init(true, parameters);

    //Generate Cipher Text With Auth Tag
    var cipherText = new byte[cipher.GetOutputSize(secretMessage.Length)];
    var len = cipher.ProcessBytes(secretMessage, 0, secretMessage.Length, cipherText, 0);
    cipher.DoFinal(cipherText, len);

    //Assemble Message
    using (var combinedStream = new MemoryStream())
    {
        using (var binaryWriter = new BinaryWriter(combinedStream))
        {
            //Prepend Nonce
            binaryWriter.Write(nonce);
            //Write Cipher Text
            binaryWriter.Write(cipherText);
        }
        return combinedStream.ToArray();
    }
}`
	SampleVulnerableHSCSHARP7 = `
<system.web>
  <authentication mode="Forms">
    <forms path="/" />
  </authentication>
</system.web>
`
	SampleSafeHSCSHARP7 = `
<system.web>
  <authentication mode="Forms">
    <forms cookieless="UseCookies" path="/" />
  </authentication>
</system.web>
`
	SampleVulnerableHSCSHARP8 = `
<system.web>
  <authentication mode="Forms">
    <forms enableCrossAppRedirects="true" path="/" />
  </authentication>
</system.web>
`
	SampleSafeHSCSHARP8 = `
<system.web>
  <authentication mode="Forms">
    <forms enableCrossAppRedirects="false" path="/" />
  </authentication>
</system.web>
`
	SampleVulnerableHSCSHARP9 = `
<system.web>
  <authentication mode="Forms">
    <forms protection="None" path="/" />
  </authentication>
</system.web>`
	SampleSafeHSCSHARP9 = `
<system.web>
  <authentication mode="Forms">
    <forms protection="All" path="/" />
  </authentication>
</system.web>`
	SampleVulnerableHSCSHARP10 = ``
	SampleSafeHSCSHARP10       = ``
	SampleVulnerableHSCSHARP11 = ``
	SampleSafeHSCSHARP11       = ``
	SampleVulnerableHSCSHARP12 = ``
	SampleSafeHSCSHARP12       = ``
	SampleVulnerableHSCSHARP13 = ``
	SampleSafeHSCSHARP13       = ``
	SampleVulnerableHSCSHARP14 = ``
	SampleSafeHSCSHARP14       = ``
	SampleVulnerableHSCSHARP15 = ``
	SampleSafeHSCSHARP15       = ``
	SampleVulnerableHSCSHARP16 = ``
	SampleSafeHSCSHARP16       = ``
	SampleVulnerableHSCSHARP17 = ``
	SampleSafeHSCSHARP17       = ``
	SampleVulnerableHSCSHARP18 = ``
	SampleSafeHSCSHARP18       = ``
	SampleVulnerableHSCSHARP19 = ``
	SampleSafeHSCSHARP19       = ``
	SampleVulnerableHSCSHARP20 = ``
	SampleSafeHSCSHARP20       = ``
	SampleVulnerableHSCSHARP21 = ``
	SampleSafeHSCSHARP21       = ``
	SampleVulnerableHSCSHARP22 = ``
	SampleSafeHSCSHARP22       = ``
	SampleVulnerableHSCSHARP23 = ``
	SampleSafeHSCSHARP23       = ``
	SampleVulnerableHSCSHARP24 = ``
	SampleSafeHSCSHARP24       = ``
	SampleVulnerableHSCSHARP25 = ``
	SampleSafeHSCSHARP25       = ``
	SampleVulnerableHSCSHARP26 = ``
	SampleSafeHSCSHARP26       = ``
	SampleVulnerableHSCSHARP27 = ``
	SampleSafeHSCSHARP27       = ``
	SampleVulnerableHSCSHARP28 = ``
	SampleSafeHSCSHARP28       = ``
	SampleVulnerableHSCSHARP29 = ``
	SampleSafeHSCSHARP29       = ``
	SampleVulnerableHSCSHARP30 = ``
	SampleSafeHSCSHARP30       = ``
	SampleVulnerableHSCSHARP31 = ``
	SampleSafeHSCSHARP31       = ``
	SampleVulnerableHSCSHARP32 = ``
	SampleSafeHSCSHARP32       = ``
	SampleVulnerableHSCSHARP33 = ``
	SampleSafeHSCSHARP33       = ``
	SampleVulnerableHSCSHARP34 = ``
	SampleSafeHSCSHARP34       = ``
	SampleVulnerableHSCSHARP35 = ``
	SampleSafeHSCSHARP35       = ``
	SampleVulnerableHSCSHARP36 = ``
	SampleSafeHSCSHARP36       = ``
	SampleVulnerableHSCSHARP37 = ``
	SampleSafeHSCSHARP37       = ``
	SampleVulnerableHSCSHARP38 = ``
	SampleSafeHSCSHARP38       = ``
	SampleVulnerableHSCSHARP39 = ``
	SampleSafeHSCSHARP39       = ``
	SampleVulnerableHSCSHARP40 = ``
	SampleSafeHSCSHARP40       = ``
	SampleVulnerableHSCSHARP41 = ``
	SampleSafeHSCSHARP41       = ``
	SampleVulnerableHSCSHARP42 = ``
	SampleSafeHSCSHARP42       = ``
	SampleVulnerableHSCSHARP43 = ``
	SampleSafeHSCSHARP43       = ``
	SampleVulnerableHSCSHARP44 = ``
	SampleSafeHSCSHARP44       = ``
	SampleVulnerableHSCSHARP45 = ``
	SampleSafeHSCSHARP45       = ``
	SampleVulnerableHSCSHARP46 = ``
	SampleSafeHSCSHARP46       = ``
	SampleVulnerableHSCSHARP47 = ``
	SampleSafeHSCSHARP47       = ``
	SampleVulnerableHSCSHARP48 = ``
	SampleSafeHSCSHARP48       = ``
	SampleVulnerableHSCSHARP49 = ``
	SampleSafeHSCSHARP49       = ``
	SampleVulnerableHSCSHARP50 = ``
	SampleSafeHSCSHARP50       = ``
	SampleVulnerableHSCSHARP51 = ``
	SampleSafeHSCSHARP51       = ``
	SampleVulnerableHSCSHARP52 = ``
	SampleSafeHSCSHARP52       = ``
	SampleVulnerableHSCSHARP53 = ``
	SampleSafeHSCSHARP53       = ``
	SampleVulnerableHSCSHARP54 = ``
	SampleSafeHSCSHARP54       = ``
	SampleVulnerableHSCSHARP55 = ``
	SampleSafeHSCSHARP55       = ``
	SampleVulnerableHSCSHARP56 = ``
	SampleSafeHSCSHARP56       = ``
	SampleVulnerableHSCSHARP57 = ``
	SampleSafeHSCSHARP57       = ``
	SampleVulnerableHSCSHARP58 = ``
	SampleSafeHSCSHARP58       = ``
	SampleVulnerableHSCSHARP59 = ``
	SampleSafeHSCSHARP59       = ``
	SampleVulnerableHSCSHARP60 = ``
	SampleSafeHSCSHARP60       = ``
	SampleVulnerableHSCSHARP61 = ``
	SampleSafeHSCSHARP61       = ``
	SampleVulnerableHSCSHARP62 = ``
	SampleSafeHSCSHARP62       = ``
	SampleVulnerableHSCSHARP63 = ``
	SampleSafeHSCSHARP63       = ``
	SampleVulnerableHSCSHARP64 = ``
	SampleSafeHSCSHARP64       = ``
	SampleVulnerableHSCSHARP65 = ``
	SampleSafeHSCSHARP65       = ``
	SampleVulnerableHSCSHARP66 = ``
	SampleSafeHSCSHARP66       = ``
	SampleVulnerableHSCSHARP67 = ``
	SampleSafeHSCSHARP67       = ``
	SampleVulnerableHSCSHARP68 = ``
	SampleSafeHSCSHARP68       = ``
	SampleVulnerableHSCSHARP69 = ``
	SampleSafeHSCSHARP69       = ``
	SampleVulnerableHSCSHARP70 = ``
	SampleSafeHSCSHARP70       = ``
	SampleVulnerableHSCSHARP71 = ``
	SampleSafeHSCSHARP71       = ``
	SampleVulnerableHSCSHARP72 = ``
	SampleSafeHSCSHARP72       = ``
	SampleVulnerableHSCSHARP73 = ``
	SampleSafeHSCSHARP73       = ``
	SampleVulnerableHSCSHARP74 = ``
	SampleSafeHSCSHARP74       = ``
)
