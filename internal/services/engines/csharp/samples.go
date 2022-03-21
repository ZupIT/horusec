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
</system.web>
`
	SampleSafeHSCSHARP9 = `
<system.web>
  <authentication mode="Forms">
    <forms protection="All" path="/" />
  </authentication>
</system.web>
`
	SampleVulnerableHSCSHARP10 = `
<system.web>
  <authentication mode="Forms">
    <forms timeout="30" path="/" />
  </authentication>
</system.web>
`
	SampleSafeHSCSHARP10 = `
<system.web>
  <authentication mode="Forms">
    <forms timeout="10" path="/" />
  </authentication>
</system.web>
`
	SampleVulnerableHSCSHARP11 = `
<httpRuntime enableHeaderChecking="false"/>
`
	SampleSafeHSCSHARP11 = `
<httpRuntime enableHeaderChecking="true"/>
`
	SampleVulnerableHSCSHARP12 = `
<httpRuntime enableVersionHeader="true"/>
`
	SampleSafeHSCSHARP12 = `
<httpRuntime enableVersionHeader="false"/>
`
	SampleVulnerableHSCSHARP13 = `
<pages enableEventValidation="false" />
`
	SampleSafeHSCSHARP13 = `
<pages enableEventValidation="true" />
`
	SampleVulnerableHSCSHARP14 = `
<sessionState timeout="30" />
`
	SampleSafeHSCSHARP14 = `
<sessionState timeout="10" />
`
	SampleVulnerableHSCSHARP15 = `
<sessionState mode="StateServer" />
`
	SampleSafeHSCSHARP15 = `
<sessionState mode="InProc" />
`
	SampleVulnerableHSCSHARP16 = `
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(options =>
  {
      options.TokenValidationParameters = new TokenValidationParameters
      {
          [...]
          RequireSignedTokens = false,
      };
  });
`
	SampleSafeHSCSHARP16 = `
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(options =>
  {
      options.TokenValidationParameters = new TokenValidationParameters
      {
          [...]
          RequireSignedTokens = true,
      };
  });
`
	SampleVulnerableHSCSHARP17 = `
CookieOptions options = new CookieOptions()
{
    Secure = false,
};
`
	SampleSafeHSCSHARP17 = `
CookieOptions options = new CookieOptions()
{
    Secure = true,
};
`
	SampleVulnerableHSCSHARP18 = `
CookieOptions options = new CookieOptions()
{
    HttpOnly = false,
};
`
	SampleSafeHSCSHARP18 = `
 CookieOptions options = new CookieOptions()
{
    HttpOnly = true,
};
`
	SampleVulnerableHSCSHARP19 = `
<system.webServer>
  <directoryBrowse enabled="true"/>
</system.webServer>
`
	SampleSafeHSCSHARP19 = `
<system.webServer>
  <directoryBrowse enabled="false"/>
</system.webServer>
`
	SampleVulnerableHSCSHARP20 = `
DirectoryEntry entry = new DirectoryEntry("LDAP://DC=PUMA}, DC=COM/");
entry.AuthenticationType = AuthenticationTypes.Anonymous; 
`
	SampleSafeHSCSHARP20 = `
DirectoryEntry entry = new DirectoryEntry("LDAP://DC=PUMA}, DC=COM/");
entry.AuthenticationType = AuthenticationTypes.Secure;
`
	SampleVulnerableHSCSHARP21 = `
using (var handler = new WebRequestHandler())
{
    handler.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

    using (var client = new HttpClient(handler))
    {
        var request = client.GetAsync(string.Format("{0}{1}", BASE_URL, endpoint)).ContinueWith((response) =>
            {
                var result = response.Result;
                var json = result.Content.ReadAsStringAsync();
                json.Wait();
                item = JsonConvert.DeserializeObject<T>(json.Result);
            }
        );
        request.Wait();
    }
}
`
	SampleSafeHSCSHARP21 = `
using (var handler = new WebRequestHandler())
{
    using (var client = new HttpClient(handler))
    {
        var request = client.GetAsync(string.Format("{0}{1}", BASE_URL, endpoint)).ContinueWith((response) =>
            {
                var result = response.Result;
                var json = result.Content.ReadAsStringAsync();
                json.Wait();
                item = JsonConvert.DeserializeObject<T>(json.Result);
            }
        );
        request.Wait();
    }
}
`
	SampleVulnerableHSCSHARP22 = `
[HttpPost]
[ValidateInput(false)]
public ActionResult Save(int id, ProductFeedbackModel model)
{
	...
}
`
	SampleSafeHSCSHARP22 = `
[HttpPost]
public ActionResult Save(int id, ProductFeedbackModel model)
{
    ...
}
`
	SampleVulnerableHSCSHARP23 = `
XmlUrlResolver resolver = new XmlUrlResolver();
resolver.Credentials = CredentialCache.DefaultCredentials;

XmlDocument xmlDoc = new XmlDocument();
xmlDoc.XmlResolver = resolver;
xmlDoc.LoadXml(xml);
`
	SampleSafeHSCSHARP23 = `
XmlDocument xmlDoc = new XmlDocument();
xmlDoc.XmlResolver = null;
xmlDoc.LoadXml(xml);
`
	SampleVulnerableHSCSHARP24 = `
DirectoryEntry entry = new DirectoryEntry("LDAP://DC=example.com, DC=COM");
DirectorySearcher searcher = new DirectorySearcher(entry);
searcher.SearchScope = SearchScope.Subtree;
searcher.Filter = string.Format("(name={0})", model.UserName);
SearchResultCollection resultCollection = searcher.FindAll();
`
	SampleSafeHSCSHARP24 = `
DirectoryEntry entry = new DirectoryEntry("LDAP://DC=example.com, DC=COM");
DirectorySearcher searcher = new DirectorySearcher(entry);
searcher.SearchScope = SearchScope.Subtree;
searcher.Filter = string.Format("(name={0})", Encoder.LdapFilterEncode(model.UserName));
SearchResultCollection resultCollection = searcher.FindAll();
`
	SampleVulnerableHSCSHARP25 = `
string q = "SELECT * FROM Items WHERE ProductCode = '" + model.ProductCode + "'";

var cfg = new Configuration();
ISessionFactory sessions = cfg.BuildSessionFactory();
ISession session = sessions.OpenSession();

var query = session.CreateQuery(q);
var product = query.List<Product>().FirstOrDefault();
`
	SampleSafeHSCSHARP25 = `
string q = "SELECT * FROM Items WHERE ProductCode = :productCode";

var cfg = new Configuration();
ISessionFactory sessions = cfg.BuildSessionFactory();
ISession session = sessions.OpenSession();

var query = session.CreateQuery(q);
var product = query
  .SetString("productCode", model.ProductCode)
  .List<Product>().FirstOrDefault();
`
	SampleVulnerableHSCSHARP26 = `
DirectoryEntry entry = new DirectoryEntry("LDAP://DC=example.com, DC=COM/");
DirectorySearcher searcher = new DirectorySearcher(entry, string.Format("(name={0})", model.UserName);
searcher.SearchScope = SearchScope.Subtree;
SearchResultCollection resultCollection = searcher.FindAll();
`
	SampleSafeHSCSHARP26 = `
DirectoryEntry entry = new DirectoryEntry("LDAP://DC=example.com, DC=COM/");
DirectorySearcher searcher = new DirectorySearcher(entry, string.Format("(name={0})", Encoder.LdapFilterEncode(model.UserName)));
searcher.SearchScope = SearchScope.Subtree;
SearchResultCollection resultCollection = searcher.FindAll();
`
	SampleVulnerableHSCSHARP27 = `
DirectoryEntry entry = new DirectoryEntry();
entry.Path = string.Format("LDAP://DC={0},DC=COM,CN=Users", model.Domain);
entry.Username = model.UserName;
entry.Password = model.Password;
DirectorySearcher searcher = new DirectorySearcher(entry);
searcher.SearchScope = SearchScope.Subtree;
searcher.Filter = $"(samaccountname=DOMAIN\\BobbyTables)";
SearchResult result = searcher.FindOne();
`
	SampleSafeHSCSHARP27 = `
DirectoryEntry entry = new DirectoryEntry();
entry.Path = string.Format("LDAP://DC={0},DC=COM,CN=Users", Encoder.LdapDistinguishedNameEncode(model.Domain));
entry.Username = model.UserName;
entry.Password = model.Password;
DirectorySearcher searcher = new DirectorySearcher(entry);
searcher.SearchScope = SearchScope.Subtree;
searcher.Filter = $"(samaccountname=DOMAIN\\BobbyTables)";
SearchResult result = searcher.FindOne();
`
	SampleVulnerableHSCSHARP28 = `
var searcher = new DirectorySearcher();
searcher.Filter = "(cn=" + input + ")";
`
	SampleSafeHSCSHARP28 = `
var searcher = new DirectorySearcher();
searcher.Filter = "(cn=" + Encoder.LdapFilterEncode(input) + ")";
`
	SampleVulnerableHSCSHARP29 = `
var cmd = "SELECT * FROM Users WHERE username = '" + input + "' and role='user'";
ctx.Database.ExecuteSqlCommand(
    cmd);
`
	SampleSafeHSCSHARP29 = `
var cmd = "SELECT * FROM Users WHERE username = @username and role='user'";
ctx.Database.ExecuteSqlCommand(
    cmd,
    new SqlParameter("@username", input));
`
	SampleVulnerableHSCSHARP30 = `
private void ConvertData(string json)
{
    var mySerializer = new JavaScriptSerializer(new SimpleTypeResolver());
    Object mything = mySerializer.Deserialize(json, typeof(SomeDataClass)/* the type doesn't matter */);
}
`
	SampleSafeHSCSHARP30 = `
private void ConvertData(string json)
{
	/* no resolver in JavaScriptSerializer parameter's */
    var mySerializer = new JavaScriptSerializer();
    Object mything = mySerializer.Deserialize(json, typeof(SomeDataClass));
}
`
	SampleVulnerableHSCSHARP31 = `
public XCLCMS.Data.Model.View.v_Comments GetModel(long CommentsID)
        {
            XCLCMS.Data.Model.View.v_Comments model = new XCLCMS.Data.Model.View.v_Comments();
            Database db = base.CreateDatabase();
            DbCommand dbCommand = db.GetSqlStringCommand("select * from v_Comments WITH(NOLOCK)   where CommentsID=" + CommentsID);
            using (var dr = db.ExecuteDataSet(dbCommand))
            {
                return XCLNetTools.DataSource.DataReaderHelper.DataReaderToEntity<XCLCMS.Data.Model.View.v_Comments>(dr);
            }
        }
`
	SampleSafeHSCSHARP31 = `
public XCLCMS.Data.Model.View.v_Comments GetModel(long CommentsID)
        {
            XCLCMS.Data.Model.View.v_Comments model = new XCLCMS.Data.Model.View.v_Comments();
            Database db = base.CreateDatabase();
            DbCommand dbCommand = db.GetSqlStringCommand("select * from v_Comments WITH(NOLOCK)   where CommentsID=@CommentsID");
            db.AddInParameter(dbCommand, "CommentsID", DbType.Int64, CommentsID);
            using (var dr = db.ExecuteDataSet(dbCommand))
            {
                return XCLNetTools.DataSource.DataReaderHelper.DataReaderToEntity<XCLCMS.Data.Model.View.v_Comments>(dr);
            }
        }
`
	SampleVulnerableHSCSHARP32 = `
public void query(string filter) {
	PreparedStatement ps = session.prepare("SELECT * FROM users WHERE uname="+filter);
	session.execute(ps);
}
`
	SampleSafeHSCSHARP32 = `
public void query(string filter) {
	PreparedStatement ps = session.prepare("SELECT * FROM users WHERE uname=?");
	ps = ps.bind('uname', filter)
	session.execute(ps);
}
`
	SampleVulnerableHSCSHARP33 = `
manager.PasswordValidator = new PasswordValidator
{
    RequiredLength = 6
};

or 

manager.PasswordValidator = new PasswordValidator();
`
	SampleSafeHSCSHARP33 = `
manager.PasswordValidator = new PasswordValidator
{
    RequiredLength = 12, // greater than 8
    RequireDigit = true, // required
    RequireLowercase = true, // required
    RequireNonLetterOrDigit = true, // required
    RequireUppercase = true // required
};
`
	SampleVulnerableHSCSHARP34 = `
<system.web>
    ...
    <httpCookies requireSSL="false" />
    ...
</system.web>
`
	SampleSafeHSCSHARP34 = `
<system.web>
    ...
    <httpCookies requireSSL="true" />
    ...
</system.web>
`
	SampleVulnerableHSCSHARP35 = `
<system.web>
    ...
    <httpCookies httpOnlyCookies="false" />
    ...
</system.web>
`
	SampleSafeHSCSHARP35 = `
<system.web>
    ...
    <httpCookies httpOnlyCookies="true" />
    ...
</system.web>
`
	SampleVulnerableHSCSHARP36 = `
  let executableXss = "<img src='xx' onerror='alert(\"XSS Performed\")'>"

  element.innerHTML = executableXss
`
	SampleSafeHSCSHARP36 = `
  let executableXss = "<img src='xx' onerror='alert(\"XSS Performed\")'>"
  
  element.textContent = executableXss
`

	SampleVulnerableHSCSHARP37 = `
manager.PasswordValidator = new PasswordValidator
{
    RequiredLength = 6
};
`
	SampleSafeHSCSHARP37 = `
manager.PasswordValidator = new PasswordValidator
{
    RequiredLength = 12, // greater than 8
    RequireDigit = true, // required
    RequireLowercase = true, // required
    RequireNonLetterOrDigit = true, // required
    RequireUppercase = true // required
};
`

	SampleVulnerableHSCSHARP38 = `
public void OnGet()
{
	Console.WriteLine("The user logged is: " + user);
}

or

public void OnGet()
{
	Message = $"The user logged is: {user}";
	_logger.LogInformation(Message);
}

or

public void OnGet()
{
	Message = $"The user logged is: {user}";
	_logger.LogError(Message);
}
`
	SampleSafeHSCSHARP38 = `
// It is recommended not to use any logs on your system.
`
	SampleVulnerableHSCSHARP39 = `
[Authorize]
public class AdminController : Controller
{
    [OutputCache]
    public ActionResult Index()
    {
        return View();
    }
}
`
	SampleSafeHSCSHARP39 = `
[Authorize]
public class AdminController : Controller
{
    public ActionResult Index()
    {
        return View();
    }
}
`
	SampleVulnerableHSCSHARP40 = `
[HttpPost]
public ActionResult LogOn(LogOnModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        if (MembershipService.ValidateUser(model.UserName, model.Password))
        {
            FormsService.SignIn(model.UserName, model.RememberMe);
            if (!String.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
        else
        {
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
        }
    }
 
    // If we got this far, something failed, redisplay form
    return View(model);
}
`
	SampleSafeHSCSHARP40 = `
[HttpPost]
public ActionResult LogOn(LogOnModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        if (MembershipService.ValidateUser(model.UserName, model.Password))
        {
            FormsService.SignIn(model.UserName, model.RememberMe);
            if (Url.IsLocalUrl(returnUrl)) // Make sure the url is relative, not absolute path
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
        else
        {
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
        }
    }
 
    // If we got this far, something failed, redisplay form
    return View(model);
}
`
	SampleVulnerableHSCSHARP41 = `public class TestController
{
    [HttpPost]
    [ValidateInput(false)]
    public ActionResult ControllerMethod(string input) {
        return f(input);
    }
}
`
	SampleSafeHSCSHARP41 = `
public class TestController
{
    [HttpPost]
    public ActionResult ControllerMethod(string input) {
        return f(input);
    }
}
`
	SampleVulnerableHSCSHARP42 = `
sql = "select sr_scenman_hid, name, remark from ras_sr_scenman_head where name  = " + ScenmanName;
                    OleDbConnection oconnection = new OleDbConnection(ModGloVariable.RasmusConn);
                    oconnection.Open();
                    OleDbCommand cmd = new OleDbCommand(sql, oconnection);
                    cmd.CommandType = System.Data.CommandType.Text;
                    OleDbDataReader reader = cmd.ExecuteReader();
`
	SampleSafeHSCSHARP42 = `
sql = "select sr_scenman_hid, name, remark from ras_sr_scenman_head where name  = @ScenmanName";
                    OleDbConnection oconnection = new OleDbConnection(ModGloVariable.RasmusConn);
                    oconnection.Open();
                    OleDbCommand cmd = new OleDbCommand(sql, oconnection);
                    cmd.CommandType = System.Data.CommandType.Text;
                    cmd.Parameters.Add("@ScenmanName", OleDbType.Char, 50).Value = ScenmanName;
                    OleDbDataReader reader = cmd.ExecuteReader();
`
	SampleVulnerableHSCSHARP43 = `
<system.web>
    ...
    <pages validateRequest="false" />
    ...
</system.web>
`
	SampleSafeHSCSHARP43 = `
<system.web>
    ...
    <pages validateRequest="true" />
    ...
</system.web>
`
	SampleVulnerableHSCSHARP44 = `
protected void btnSearch_Click(object sender, EventArgs e) { 
	SqlConnection conn = new SqlConnection(@"Data Source=ServerName\SQLEXPRESS;Initial Catalog=DemoDB;Integrated Security=SSPI;");
	SqlCommand cmd = new SqlCommand("Select * from GridViewDynamicData where Field1= '" + txtSearch.Text +"'", conn);
	conn.Open();
	SqlDataAdapter ad = new SqlDataAdapter(cmd);
	DataTable dt = new DataTable();
	ad.Fill(dt);
	if(dt.Rows.Count > 0)
	{
		GridView1.DataSource = dt;
		GridView1.DataBind();
	}
	conn.Close();
}
`
	SampleSafeHSCSHARP44 = `
protected void btnSearch_Click(object sender, EventArgs e) { 
	DataTable dt = new DataTable();
	using (SqlConnection sqlConn = new SqlConnection(ConfigurationManager.ConnectionStrings["DBConnection"].ConnectionString)){
		string sql = "SELECT * FROM GridViewDynamicData WHERE Field1 = @SearchText";
		using(SqlCommand sqlCmd = new SqlCommand(sql,sqlConn)){
			sqlCmd.Parameters.AddWithValue("@SearchText", txtSearch.Text);
			sqlConn.Open();
			using(SqlDataAdapter sqlAdapter = new SqlDataAdapter(sqlCmd)){
				sqlAdapter.Fill(dt);
			}
		}
	}
	
	if(dt.Rows.Count > 0){
		GridView1.DataSource = dt;
		GridView1.DataBind();
	}
}

`
	SampleVulnerableHSCSHARP45 = `
<system.web>
   ...
   <httpRuntime [..] requestValidationMode="2.0" [..]/>
   ...
</system.web>
`
	SampleSafeHSCSHARP45 = `
<system.web>
   ...
   <httpRuntime [..] requestValidationMode="4.5" [..]/>
   ...
</system.web>
`
	SampleVulnerableHSCSHARP46 = `
var cmd = "SELECT * FROM Users WHERE username = '" + input + "' and role='user'";
ctx.Database.ExecuteSqlCommand(
    cmd);
`
	SampleSafeHSCSHARP46 = `
var cmd = "SELECT * FROM Users WHERE username = @username and role='user'";
ctx.Database.ExecuteSqlCommand(
    cmd,
    new SqlParameter("@username", input));
`
	SampleVulnerableHSCSHARP47 = `
<system.web>
   ...
   <pages [..] viewStateEncryptionMode="Auto" [..]/>
   ...
</system.web>

or 


<system.web>
   ...
   <pages [..] viewStateEncryptionMode="Never" [..]/>
   ...
</system.web>
`
	SampleSafeHSCSHARP47 = `
<system.web>
   ...
   <pages [..] viewStateEncryptionMode="Always" [..]/>
   ...
</system.web>
`
	SampleVulnerableHSCSHARP48 = `
string q = "SELECT * FROM Items WHERE ProductCode = '" + model.ProductCode + "'";

var cfg = new Configuration();
ISessionFactory sessions = cfg.BuildSessionFactory();
ISession session = sessions.OpenSession();

var query = session.CreateSqlQuery(q);
var product = query.List<Product>().FirstOrDefault();
`
	SampleSafeHSCSHARP48 = `
string q = "SELECT * FROM Items WHERE ProductCode = :productCode";

var cfg = new Configuration();
ISessionFactory sessions = cfg.BuildSessionFactory();
ISession session = sessions.OpenSession();

var query = session.CreateSqlQuery(q);
var product = query
  .SetParameter("productCode", model.ProductCode)
  .List<Product>().FirstOrDefault();
`
	SampleVulnerableHSCSHARP49 = `
<system.web>
    ...
    <pages enableViewStateMac="false" />
    ...
</system.web>
`
	SampleSafeHSCSHARP49 = `
<system.web>
    ...
    <pages enableViewStateMac="true" />
    ...
</system.web>
`
	SampleVulnerableHSCSHARP50 = `
        public void Append(string name, byte[] data, long expectedVersion)
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var version = MakeSureLastVersionMatches(name, expectedVersion, conn, tx);

                    const string txt =
                           @"";

                    using (var cmd = new NpgsqlCommand(
								"INSERT INTO ES_Events2 (CustomerId, Name, Version, Data)
                                VALUES("+customerId+","+name+","+(version+1)+","+data+")",
								conn, tx))
                    {
                        cmd.ExecuteNonQuery();
                    }
                    tx.Commit();
                }
            }
        }
`
	SampleSafeHSCSHARP50 = `
        public void Append(string name, byte[] data, long expectedVersion)
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var version = MakeSureLastVersionMatches(name, expectedVersion, conn, tx);

                    const string txt =
                           @"INSERT INTO ES_Events2 (CustomerId, Name, Version, Data)
                                VALUES(:customerId, :name, :version, :data)";

                    using (var cmd = new NpgsqlCommand(txt, conn, tx))
                    {
                        cmd.Parameters.AddWithValue(":name", name);
                        cmd.Parameters.AddWithValue(":version", version+1);
                        cmd.Parameters.AddWithValue(":data", data);
                        cmd.Parameters.AddWithValue(":customerId", customerId);
                        cmd.ExecuteNonQuery();
                    }
                    tx.Commit();
                }
            }
        }
`
	SampleVulnerableHSCSHARP51 = `
using (var handler = new WebRequestHandler())
{
    handler.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

    using (var client = new HttpClient(handler))
    {
        var request = client.GetAsync(string.Format("{0}{1}", BASE_URL, endpoint)).ContinueWith((response) =>
            {
                var result = response.Result;
                var json = result.Content.ReadAsStringAsync();
                json.Wait();
                item = JsonConvert.DeserializeObject<T>(json.Result);
            }
        );
        request.Wait();
    }
}
`
	SampleSafeHSCSHARP51 = `
using (var handler = new WebRequestHandler())
{
    using (var client = new HttpClient(handler))
    {
        var request = client.GetAsync(string.Format("{0}{1}", BASE_URL, endpoint)).ContinueWith((response) =>
            {
                var result = response.Result;
                var json = result.Content.ReadAsStringAsync();
                json.Wait();
                item = JsonConvert.DeserializeObject<T>(json.Result);
            }
        );
        request.Wait();
    }
}
`
	SampleVulnerableHSCSHARP52 = `
DES DESalg = DES.Create();

// Create a string to encrypt. 
byte[] encrypted;
ICryptoTransform encryptor = DESalg.CreateEncryptor(key, zeroIV);

// Create the streams used for encryption. 
using (MemoryStream msEncrypt = new MemoryStream())
{
    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt,
                                                     encryptor,
                                                     CryptoStreamMode.Write))
    {
        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
        {
            //Write all data to the stream.
            swEncrypt.Write(Data);
        }
        encrypted = msEncrypt.ToArray();
        return encrypted;
    }
}
`
	SampleSafeHSCSHARP52 = `
// Create a string to encrypt. 
byte[] encrypted;
var encryptor = new AesManaged();
encryptor.Key = key;
encryptor.GenerateIV();
var iv = encryptor.IV;

// Create the streams used for encryption. 
using (MemoryStream msEncrypt = new MemoryStream())
{
    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt,
                                                     encryptor.CreateEncryptor(),
                                                     CryptoStreamMode.Write))
    {
        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
        {
            //Write all data to the stream.
            swEncrypt.Write(Data);
        }
        encrypted = msEncrypt.ToArray();
        return encrypted;
    }
}
`
	SampleVulnerableHSCSHARP53 = `
<div class="loginDisplay">
    @Html.Raw(string.Format("Welcome <span class=\"bold\">{0}</span>!", Model.UserName))
</div>
`
	SampleSafeHSCSHARP53 = `
<div class="loginDisplay">
    Welcome <span class="bold">@Model.UserName</span>!
</div>
`
	SampleVulnerableHSCSHARP54 = `
<system.web>
    ...
    <customErrors mode="Off" defaultRedirect="/home/error"/>
    ...
</system.web>
`
	SampleSafeHSCSHARP54 = `
<system.web>
    ...
    <customErrors mode="RemoteOnly|On" defaultRedirect="/home/error"/>
    ...
</system.web>
`
	SampleVulnerableHSCSHARP55 = `
public class AdminController : Controller
{
    public string GetScript(string param) {
        return "<script>" + param + "</script>"
    }
}
`
	SampleSafeHSCSHARP55 = `
public class AdminController : Controller
{
    public string GetScript() {
        return "<script> console.log('example') </script>"
    }
}
`
	SampleVulnerableHSCSHARP56 = `
    public static List<Auspiciante> getAllAuspiciantes(string name)
    {
        OdbcConnection con = ConexionBD.ObtenerConexion();
        DataSet ds = new DataSet();
        List<Auspiciante> listaAuspiciantes = new List<Auspiciante>();
        try
        {
            OdbcCommand cmd = new OdbcCommand("SELECT a.id, a.image FROM auspiciante a Where a.name = " + name, con);
            cmd.CommandType = CommandType.Text;
            OdbcDataReader dr = cmd.ExecuteReader();

            while (dr.Read())
            {
                Auspiciante a = new Auspiciante();
                a.IdAuspiciante = dr.GetInt32(dr.GetOrdinal("id"));
                a.ImagenAuspiciante = ImagenDAL.getImagen(con,dr.GetInt32(dr.GetOrdinal("imagen")));

                listaAuspiciantes.Add(a);
            }
        }
        catch (Exception e)
        {
            throw new SportingException("Ocurrio un problema al intentar obtener los auspiciantes. " + e.Message);
        }
        return listaAuspiciantes;
    }
`
	SampleSafeHSCSHARP56 = `
public static List<Auspiciante> getAllAuspiciantes(string name)
{
	OdbcConnection con = ConexionBD.ObtenerConexion();
	DataSet ds = new DataSet();
	List<Auspiciante> listaAuspiciantes = new List<Auspiciante>();
	try
	{
		OdbcCommand cmd = new OdbcCommand("SELECT a.id, a.image FROM auspiciante a Where a.name = ?", con);
		command.Parameters.Add(new OdbcParameter("name", name));
		cmd.CommandType = CommandType.Text;
		OdbcDataReader dr = cmd.ExecuteReader();

		while (dr.Read())
		{
			Auspiciante a = new Auspiciante();
			a.IdAuspiciante = dr.GetInt32(dr.GetOrdinal("id"));
			a.ImagenAuspiciante = ImagenDAL.getImagen(con,dr.GetInt32(dr.GetOrdinal("imagen")));

			listaAuspiciantes.Add(a);
		}
	}
	catch (Exception e)
	{
		throw new SportingException("Ocurrio un problema al intentar obtener los auspiciantes. " + e.Message);
	}
	return listaAuspiciantes;
}
`
	SampleVulnerableHSCSHARP57 = `
HashAlgorithm hash = new SHA1CryptoServiceProvider();
byte[] bytes = hash.ComputeHash(input);
`
	SampleSafeHSCSHARP57 = `
HashAlgorithm hash = new SHA512Managed();
byte[] bytes = hash.ComputeHash(input);
`
	SampleVulnerableHSCSHARP58 = `
using (MemoryStream mStream = new MemoryStream())
{
    //Input bytes
    byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);

    SymmetricAlgorithm alg = new DESCryptoServiceProvider();

    //Set key and iv
    alg.Key = GetKey();
    alg.IV = GetIv();

    //Create the crypto stream
    CryptoStream cStream = new CryptoStream(mStream, alg.CreateEncryptor(), CryptoStreamMode.Write);
    cStream.Write(inputBytes, 0, inputBytes.Length);
    cStream.FlushFinalBlock();
    cStream.Close();

    //Get the output
    output = mStream.ToArray();

    //Close resources
    mStream.Close();
    alg.Clear();
}
`
	SampleSafeHSCSHARP58 = `
using (MemoryStream mStream = new MemoryStream())
{
    //Input bytes
    byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);

    SymmetricAlgorithm alg = new AesManaged();

    //Set key and iv
    alg.Key = GetKey();
    alg.IV = GetIv();

    //Create the crypto stream
    CryptoStream cStream = new CryptoStream(mStream, alg.CreateEncryptor(), CryptoStreamMode.Write);
    cStream.Write(inputBytes, 0, inputBytes.Length);
    cStream.FlushFinalBlock();
    cStream.Close();

    //Get the output
    output = mStream.ToArray();

    //Close resources
    mStream.Close();
    alg.Clear();
}
`
	SampleVulnerableHSCSHARP59 = `
using (MemoryStream mStream = new MemoryStream())
{
    //Input bytes
    byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);

    SymmetricAlgorithm alg = Aes.Create();
    alg.Mode = CipherMode.ECB;

    //Set key and iv
    alg.Key = GetKey();
    alg.IV = GetIv();

    //Create the crypto stream
    CryptoStream cStream = new CryptoStream(mStream
      , alg.CreateEncryptor()
      , CryptoStreamMode.Write);
    cStream.Write(inputBytes, 0, inputBytes.Length);
    cStream.FlushFinalBlock();
    cStream.Close();

    //Get the output
    output = mStream.ToArray();

    //Close resources
    mStream.Close();
    alg.Clear();
}
`
	SampleSafeHSCSHARP59 = `
//Perform integrity check on incoming data
string[] args = model.ProtectedData.Split('.');
byte[] ciphertext = Convert.FromBase64String(args[0]);
byte[] hmac = Convert.FromBase64String(args[1]);

HMACSHA256 hmac = new HMACSHA256(_KEY);
byte[] verification = hmac.ComputeHash(ciphertext);

if (!verification.SequenceEqual(hmac))
    throw new ArgumentException("Invalid signature detected.");

using (MemoryStream mStream = new MemoryStream())
{
    SymmetricAlgorithm alg = Aes.Create();
    alg.Mode = CipherMode.CBC;

    //Set key and iv
    alg.Key = GetKey();
    alg.IV = GetIv();

    //Create the crypto stream
    CryptoStream cStream = new CryptoStream(mStream
      , alg.CreateDecryptor()
      , CryptoStreamMode.Write);
    cStream.Write(ciphertext, 0, inputBytes.Length);
    cStream.FlushFinalBlock();
    cStream.Close();

    //Get the cleartext
    byte[] cleartext = mStream.ToArray();

    //Close resources
    mStream.Close();
    alg.Clear();
}
`
	SampleVulnerableHSCSHARP60 = `
<system.web>
    ...
    <compilation debug="true" targetFramework="4.5"/>
    ...
</system.web>
`
	SampleSafeHSCSHARP60 = `
<system.web>
    ...
    <compilation debug="false" targetFramework="4.5"/>
    ...
</system.web>
`
	SampleVulnerableHSCSHARP61 = `
<package id="bootstrap" version="3.0.0" targetFramework="net462" />
`
	SampleSafeHSCSHARP61 = `
<package id="bootstrap" version="4.5.3" targetFramework="net462" />
`
	SampleVulnerableHSCSHARP62 = `
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    ...
    app.UseCors(builder => builder.AllowAnyOrigin());
    ...
}
`
	SampleSafeHSCSHARP62 = `
private readonly string secureOrigin = "_secureOrigin";

public void ConfigureServices(IServiceCollection services)
{
    services.AddCors(options =>
    {
        options.AddPolicy(MyAllowSpecificOrigins,
        builder =>
        {
            builder.WithOrigins("https://www.pumasecurity.io",
                                "https://www.pumascan.com");
        });
    });
}

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
   ...
   app.UseCors(secureOrigin);
   ...
}
`
	SampleVulnerableHSCSHARP63 = `
[HttpPost]
public ActionResult Enter(int id, ContestEntryModel model)
{
    if (ModelState.IsValid)
    {
        submitContestEntry(id, model);
    }
}
`
	SampleSafeHSCSHARP63 = `
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult Enter(int id, ContestEntryModel model)
{
    if (ModelState.IsValid)
    {
        submitContestEntry(id, model);
    }
}
`
	SampleVulnerableHSCSHARP64 = `
protected void LoginUser_LoggedIn(object sender, EventArgs e)
{
    if (Request.QueryString["ReturnUrl"] != null)
        Response.Redirect(Request.QueryString["ReturnUrl"]);
}
`
	SampleSafeHSCSHARP64 = `
protected void LoginUser_LoggedIn(object sender, EventArgs e)
{
    Uri targetUri = null;

    if (Uri.TryCreate(Request.QueryString["ReturnUrl"], UriKind.Relative, out targetUri))
    {
        Response.Redirect(targetUri.ToString());
    }
    else
    {
        Response.Redirect("~/default.aspx");
    }
}
`
	SampleVulnerableHSCSHARP65 = `
public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
{
    var user = await _userManager.FindByNameAsync(model.Username);
    [...]
    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
    [...]
};
`
	SampleSafeHSCSHARP65 = `
{
    var user = await _userManager.FindByNameAsync(model.Username);
    [...]
    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, true);
    [...]
};
`
	SampleVulnerableHSCSHARP66 = `
<h2>
    Welcome <%= Request["UserName"].ToString() %>
</h2>
`
	SampleSafeHSCSHARP66 = `
<h2>
    Welcome <%: Request["UserName"].ToString() %>
</h2>
`
	SampleVulnerableHSCSHARP67 = `
<asp:GridView ID="gv" runat="server" ItemType="Data.Product">
    <Columns>
        <asp:TemplateField HeaderText="Product">
            <ItemTemplate>
                <%# Item.ProductName %>
            </ItemTemplate>
        </asp:TemplateField>
    </Columns>
</asp:GridView>
`
	SampleSafeHSCSHARP67 = `
<asp:GridView ID="gv" runat="server" ItemType="Data.Product">
    <Columns>
        <asp:TemplateField HeaderText="Product">
            <ItemTemplate>
                <%#: Item.ProductName %>
            </ItemTemplate>
        </asp:TemplateField>
    </Columns>
</asp:GridView>
`
	SampleVulnerableHSCSHARP68 = `
<div class="loginDisplay">
@{
    WriteLiteral(string.Format("Welcome <span class=\"bold\">{0}</span>!", Model.UserName));
}
</div>
`
	SampleSafeHSCSHARP68 = `
<div class="loginDisplay">
    Welcome <span class="bold">@Model.UserName</span>!
</div>
`
	SampleVulnerableHSCSHARP69 = `
litDetails.Text = product.ProductDescription;
`
	SampleSafeHSCSHARP69 = `
litDetails.Text = Encoder.HtmlEncode(product.ProductDescription);
`
	SampleVulnerableHSCSHARP70 = `
lblDetails.Text = product.ProductDescription;
`
	SampleSafeHSCSHARP70 = `
lblDetails.Text = Encoder.HtmlEncode(product.ProductDescription);
`
	SampleVulnerableHSCSHARP71 = `
public static byte[] GenerateRandomBytes(int length)
{
    var random = new Random();
    byte[] bytes = new byte[length];
    random.NextBytes(bytes);
    return bytes;
}
`
	SampleSafeHSCSHARP71 = `
public static byte[] GenerateSecureRandomBytes(int length)
{
    var random = new RNGCryptoServiceProvider();
    byte[] bytes = new byte[length];
    random.GetNonZeroBytes(bytes);
    return bytes;
}
`
	SampleVulnerableHSCSHARP72 = `
RSACryptoServiceProvider alg = new RSACryptoServiceProvider(1024);
`
	SampleSafeHSCSHARP72 = `
RSACryptoServiceProvider alg = new RSACryptoServiceProvider(2048);
`
	SampleVulnerableHSCSHARP73 = `
XmlReaderSettings rs = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Parse,
};

XmlReader reader = XmlReader.Create("evil.xml", rs);
while (reader.Read())
`
	SampleSafeHSCSHARP73 = `
XmlReaderSettings rs = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
};

XmlReader reader = XmlReader.Create("evil.xml", rs);
while (reader.Read())
`
	SampleVulnerableHSCSHARP74 = `
DirectoryEntry entry = new DirectoryEntry(string.Format("LDAP://DC={0}, DC=COM/", model.Domain));
DirectorySearcher searcher = new DirectorySearcher(entry);
searcher.SearchScope = SearchScope.Subtree;
searcher.Filter = "(name={BobbyTables})";
SearchResultCollection resultCollection = searcher.FindAll();
`
	SampleSafeHSCSHARP74 = `
DirectoryEntry entry = new DirectoryEntry(string.Format("LDAP://DC={0}, DC=COM/", Encoder.LdapDistinguishedNameEncode(model.Domain));
DirectorySearcher searcher = new DirectorySearcher(entry);
searcher.SearchScope = SearchScope.Subtree;
searcher.Filter = "(name={BobbyTables})";
SearchResultCollection resultCollection = searcher.FindAll();
`
)
