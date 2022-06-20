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

package dart

const (
	SampleVulnerableHSDART1 = `
...
final CpfExposedFromUserInput = "";
...
void onButtonClick() async {
	try {
		var value = await ValidateCPFPost(CpfExposedFromUserInput)
		SharedPreferences prefs = await SharedPreferences.getInstance();

		// Possible Vulnerable Code: exposed identity of the user in local machine
		prefs.setString('cpf', CpfExposedFromUser);
		...
	} on HttpException {
		...
	}
}
...
`
	SampleSafeHSDART1 = `
...
final CpfExposedFromUserInput = "";
...
void onButtonClick() async {
	try {
        // Safe code: Because not log information sensitive and only sent to backend api. 
		var value = await ValidateCPFPost(CpfExposedFromUserInput)
		...
	} on HttpException {
		...
	}
}
...
`

	SampleVulnerableHSDART2 = `
...
  FirebaseMessaging _firebaseMessaging = FirebaseMessaging();
  
  @override
  void initState() {
    ...
    super.initState();
    _firebaseMessaging.configure(
      // Possible vulnerable code: exposed sensitive information on application log or in notification of the user
      onMessage: (Map<String, dynamic> response) async {
        print("onMessage: $response");
        ...
      },
      onLaunch: (Map<String, dynamic> response) async {
        print("onLaunch: $response");
        ...
      },
      onResume: (Map<String, dynamic> response) async {
        print("onResume: $response");
        ...
      },
    );
  }
...
`
	SampleSafeHSDART2 = `
...
  FirebaseMessaging _firebaseMessaging = FirebaseMessaging();
  
  @override
  void initState() {
    ...
    super.initState();
    // Safe code: Because not log information sensitive and only sent to backend api.
    _firebaseMessaging.configure(
      onLaunch: (Map<String, dynamic> response) async {
        sendToAPI(response);
        ...
      },
    );
  }
...
`

	SampleVulnerableHSDART3 = `
List<BiometricType> availableBiometrics;
    await auth.getAvailableBiometrics();

if (Platform.isIOS) {
    if (availableBiometrics.contains(BiometricType.face)) {
        // Face ID.
    } else if (availableBiometrics.contains(BiometricType.fingerprint)) {
        // Touch ID.
    }
}
`
	SampleSafeHSDART3 = `// Don't use biometric mode `

	SampleVulnerableHSDART4 = `
// Possible vulnerable code: user can pass other path in your input and causes attacks in the application.
final file = new File(FileFromUserInput);
final document = XmlDocument.parse(file.readAsStringSync());
`
	SampleSafeHSDART4 = `
final file = new File('static-file.xml');
final document = XmlDocument.parse(file.readAsStringSync());
`

	SampleVulnerableHSDART5 = `
...
static Future<HttpServer> SentToApi(
	int port,
	SecurityContext context,
	{int backlog = 0,
	bool v6Only = false,
	bool requestClientCertificate = false,
	bool shared = false}
) {
    // Possible vulnerable code: HTTP without SSL is not secure. 
    return _HttpServer.bindSecure('http://my-api.com.br', port, context, backlog, v6Only, requestClientCertificate, shared);
}
`
	SampleSafeHSDART5 = `
static Future<HttpServer> SentToApi(
	int port,
	SecurityContext context,
	{int backlog = 0,
	bool v6Only = false,
	bool requestClientCertificate = false,
	bool shared = false}
) => _HttpServer.bindSecure('https://my-api.com.br', port, context, backlog, v6Only, requestClientCertificate, shared);
`

	SampleVulnerableHSDART6 = `
import 'package:flutter_sms/flutter_sms.dart';
`
	SampleSafeHSDART6 = `// You can't use flutter_sms library`

	SampleVulnerableHSDART7 = `
import 'package:sprintf/sprintf.dart';
import 'dart:html';
...

void RenderHTML(String content) {
	// Possible vulnerable code: In your html you can receive variable and sent to html render in this case occurs XSS attack 
	var element = new Element.html(sprintf("<div class="foo">%s</div>", [content]));
	document.body.append(element);
}
`
	SampleSafeHSDART7 = `
import 'package:sprintf/sprintf.dart';
import 'dart:html';
...

void RenderHTML(String content) {
	var element = new DivElement()
		..textContent = content;
	document.body.append(element);
}
`

	SampleVulnerableHSDART8 = `
import 'package:sprintf/sprintf.dart';
import 'package:logging/logging.dart';
...
final _logger = Logger('YourClassName');

void ShowUserSensitiveInformation(String identity) {
	// Possible vulnerable code: Logging Sensitive information is not good implementation 
	print(sprintf("User identity is: %s", [identity]));
	// or Possible vulnerable code: Logging Sensitive information is not good implementation 
	_logger.info(sprintf("User identity is: %s", [identity]));
	sentToAPIUserIdentity(identity);
}
`
	SampleSafeHSDART8 = `
import 'package:logging/logging.dart';
...
final _logger = Logger('YourClassName');

void ShowUserSensitiveInformation(String identity) {
	print("send identity of the user to api");
	_logger.info("send identity of the user to api");
	sentToAPIUserIdentity(identity);
}
...
`

	SampleVulnerableHSDART9 = `
import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;

///Generate MD5 hash
generateMd5(String data) {
  var content = new Utf8Encoder().convert(data);
  var md5 = crypto.md5;
  // Possible vulnerable code: This code is bad because this type cryptography is easy of to be broken.
  var digest = md5.convert(content);
  return hex.encode(digest.bytes);
}
`
	SampleSafeHSDART9 = `
import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;

///Generate sha256 hash
generateSha256(String data) {
  var content = new Utf8Encoder().convert(data);
  var sha256 = crypto.sha256;
  var digest = sha256.convert(content);
  return hex.encode(digest.bytes);
}
`

	SampleVulnerableHSDART10 = `
final SecurityContext context = SecurityContext(withTrustedRoots: false);
// Possible vulnerable code: This code is bad because if you can exposed for MITM attacks
context.setTrustedCertificates("client.cer");
Socket socket = await Socket.connect(serverIp, port);
socket = await SecureSocket.secure(socket, host: "server"
  , context: context, onBadCertificate: (cert) => true);
`
	SampleSafeHSDART10 = `
final SecurityContext context = SecurityContext(withTrustedRoots: false);
Socket socket = await Socket.connect(serverIp, port);
socket = await SecureSocket.secure(socket, host: "server"
  , context: context, onBadCertificate: (cert) => true);
`

	SampleVulnerableHSDART11 = `
try {
// Possible vulnerable code: This code is bad because your authentication can be passed easy form when exists only 1 method to authenticate
  authenticated = await auth.authenticateWithBiometrics(
	  localizedReason: 'Touch your finger on the sensor to login',
	  useErrorDialogs: true,
	  stickyAuth: false
  );
} catch (e) {
  print("error using biometric auth: $e");
}
`
	SampleSafeHSDART11 = `
try {
  authenticated = await auth.CheckTwoFactorAuthenticationAndAuthenticateWithBiometrics(
	  localizedReason: 'Touch your finger on the sensor to login',
	  useErrorDialogs: true,
	  stickyAuth: false
  );
} catch (e) {
  print("error using biometric auth: $e");
}
`

	SampleVulnerableHSDART12 = `
_getFromClipboard() async {
	// Possible vulnerable code: Is not good idea read content from clipboard.
	Map<String, dynamic> result = await SystemChannels.platform.invokeMethod('Clipboard.getData');
	if (result != null) {
	  return result['text'].toString();
	}
	return '';
}

void sendToAPIToKeepChangesInDatabase() {
	try {
		String changesFromClipboard = await _getFromClipboard()
		if (changesFromClipboard != "" {
            // Here occurs SQL Injection, XSS attack, and others many forms to users attack your base of data when you safe content without treatment.
			SaveChangesFromClipboardOnDatabasePost(changesFromClipboard)
		}
	} on HttpException {
		...
	}
}
`
	SampleSafeHSDART12 = `
_getFromClipboard() async {
	var cp = Clipboard
	Map<String, dynamic> result = await cp.getData;
	if (result != null) {
	  return "New content has been updated on Clipboard";
	}
	return "Not exists content from Clipboard";
}

void sendToAPIToKeepChangesInDatabase() {
	try {
		String changesFromClipboard = await _getFromClipboard()
		if (changesFromClipboard != "" {
            // Note this code is safe because only data on sent to API is constants, there not exists vulnerabilities
			SaveChangesFromClipboardOnDatabasePost(changesFromClipboard)
		}
	} on HttpException {
		...
	}
}
`

	SampleVulnerableHSDART13 = `
Database database = await openDatabase(path, version: 1,
    onCreate: (Database db, int version) async {
  await db.execute('CREATE TABLE Users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);');
});

getCheckIfUserExists(String username) {
	try {
		// Possible vulnerable code: User can be pass malicious code and delete all data from your database by example.
		List<Map> list = await database.rawQuery("SELECT * FROM Users WHERE username = '" + username + "';");
		...
	} on Exception {
    	...
	}
}
`
	SampleSafeHSDART13 = `
Database database = await openDatabase(path, version: 1,
    onCreate: (Database db, int version) async {
  await db.execute('CREATE TABLE Users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);');
});

getCheckIfUserExists(String username) {
	try {
		List<Map> list = await database.rawQuery("SELECT * FROM Users WHERE username = ?;", [username]);
		...
	} on Exception {
    	...
	}
}
`

	SampleVulnerableHSDART14 = `
// Possible vulnerable code: If You get NSTemporaryDirectory you can get anywhere content from this directory
let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true);
`
	SampleSafeHSDART14 = `
let temporaryDirectoryURL = URL(fileURLWithPath: "Some/Other/Path", isDirectory: true)
`

	SampleVulnerableHSDART15 = `
// Possible vulnerable code: This code is bad because this type cryptography is easy of to be broken.
final encrypter = Encrypter(AES(key, mode: AESMode.cts));
`
	SampleSafeHSDART15 = `
final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
`

	SampleVulnerableHSDART16 = `
HttpServer.bind('127.0.0.1', 8080).then((server){
	server.listen((HttpRequest request){     
		request.uri.queryParameters.forEach((param,val){
			print(param + '-' + val);
		});
		
		// Possible vulnerable code: When you allow any origin you can exposed to multiple attacks in your application
		request.response.headers.add("Access-Control-Allow-Origin", "*");
		request.response.headers.add("Access-Control-Allow-Methods", "POST,GET,DELETE,PUT,OPTIONS");
		
		request.response.statusCode = HttpStatus.OK;
		request.response.write("Success!");
		request.response.close();
    });
});
`
	SampleSafeHSDART16 = `
HttpServer.bind('127.0.0.1', 8080).then((server){
	server.listen((HttpRequest request){     
		request.uri.queryParameters.forEach((param,val){
			print(param + '-' + val);
		});
		
		request.response.headers.add("Access-Control-Allow-Origin", "only-my-website.com.br");
		request.response.headers.add("Access-Control-Allow-Methods", "POST,GET,DELETE,PUT,OPTIONS");
		
		request.response.statusCode = HttpStatus.OK;
		request.response.write("Success!");
		request.response.close();
    });
});
`

	SampleVulnerableHSDART17 = `
getIPFromLoggedUser (List<String> UserParams) async {
	// Possible vulnerable code: User can be inject malicious code and run others commands after this command 
	var result = await Process.run("netcfg", [UserParams]);
	return result.stdout
}
`
	SampleSafeHSDART17 = `
// You can get IP using library or interact with your backend application
var getIPFromLoggedUser => await MyIpPost()
`
)
