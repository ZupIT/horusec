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

package jvm

const (
	SampleVulnerableHSJVM1 = `
public class SomeClass {
    public static User getUser(string id)
    {
        Logger log = Logger.getLogger("com.api.jar");
        User user = _repository.getUser(id);
        log.info("the user requested is: " + user);
    }
}
`
	SampleSafeHSJVM1 = `
public class SomeClass {
    public static User getUser(string id)
    {
		// Don't use log in your system
        return _repository.getUser(id);
    }
}
`

	SampleVulnerableHSJVM2 = `
import http.client.HttpClient;

public class Foo {
    ...
}
`
	SampleSafeHSJVM2 = `
// Don't use http client without tls
public class Foo {
    ...
}
`

	SampleVulnerableHSJVM3 = `
dependencies {
    compile 'com.google.android.gms.safetynet.SafetyNetApi:11.0.4'
}
`
	SampleSafeHSJVM3 = `
dependencies {
	// don't use SafetyNetApi
}
`

	SampleVulnerableHSJVM4 = `
import android.content.ContentProvider;

public class Foo {
    ...
}
`
	SampleSafeHSJVM4 = `
// Don't use ContentProvider library

public class Foo {
    ...
}
`

	SampleVulnerableHSJVM5 = `
_ = digestData.withUnsafeMutableBytes {digestBytes in
    messageData.withUnsafeBytes {messageBytes in
        CC_MD5(messageBytes, CC_LONG(messageData.count), digestBytes)
    }
  }
`
	SampleSafeHSJVM5 = `
// Use sha256 and with safe bytes generations
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
`

	SampleVulnerableHSJVM6 = `
// Vulnerable mode is:
Keychain
or 
kSecAttrAccessibleWhenUnlocked
or 
kSecAttrAccessibleAfterFirstUnlock
or 
SecItemAdd
or 
SecItemUpdate
or 
NSDataWritingFileProtectionComplete
`
	SampleSafeHSJVM6 = `
// safe mode is:
kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
`

	SampleVulnerableHSJVM7 = `
UIWebView
`
	SampleSafeHSJVM7 = `
// Don't use web view component.`

	SampleVulnerableHSJVM8 = `
@Override
public String encrypt(String value) throws Exception{
  return AESCrypt.encrypt(passPhrase, value);
}
`
	SampleSafeHSJVM8 = `
// Use sha256 and with safe bytes generations
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
}
`

	SampleVulnerableHSJVM9 = `
PDKeychainBindings
`
	SampleSafeHSJVM9 = `
// Don't use this method of keychain access
`

	SampleVulnerableHSJVM10 = `
//wrong: should use remaining size of dest
strncat(dest, src, strlen(dest));
`
	SampleSafeHSJVM10 = `
// Don't use this method of keychain access
`

	SampleVulnerableHSJVM11 = `
request.validatesSecureCertificate = NO;
or
allowInvalidCertificates = YES;
or
canAuthenticateAgainstProtectionSpace
or
continueWithoutCredentialForAuthenticationChallenge
or
kCFStreamSSLAllowsExpiredCertificates
or
kCFStreamSSLAllowsAnyRoot
or
kCFStreamSSLAllowsExpiredRoots
`
	SampleSafeHSJVM11 = `
request.validatesSecureCertificate = YES;
or
request.allowInvalidCertificates = NO;
`

	SampleVulnerableHSJVM12 = `
setAllowsAnyHTTPSCertificate: YES
or
allowsAnyHTTPSCertificateForHost
or
loadingUnvalidatedHTTPSPage = yes
`
	SampleSafeHSJVM12 = `
setAllowsAnyHTTPSCertificate: no
or
loadingUnvalidatedHTTPSPage = no
`

	SampleVulnerableHSJVM13 = `
[[NSNotificationCenter defaultCenter] postNotificationName:UIPasteboardChangedNotification object:[UIPasteboard generalPasteboard]];
or 
[UIPasteboard generalPasteboard].string = @"your string";
NSString *str =  [UIPasteboard generalPasteboard].string];
`
	SampleSafeHSJVM13 = `
// Don't get content from clipboard
`

	SampleVulnerableHSJVM14 = `
sqlite3_exec(...)
`
	SampleSafeHSJVM14 = `
// Dont't use sqlite executable directly
`

	SampleVulnerableHSJVM15 = `
const tempDirectory NSTemporaryDirectory = new NSTemporaryDirectory()
`
	SampleSafeHSJVM15 = `
// Don't use temporary directory `

	SampleVulnerableHSJVM16 = `
var clipboard = UIPasteboard()
`
	SampleSafeHSJVM16 = `
// Don't past content from clipboard
`

	SampleVulnerableHSJVM17 = `
import android.app.DownloadManager

...
var foo = mContext.getSystemService(Context.DOWNLOAD_SERVICE); 
`
	SampleSafeHSJVM17 = `
import android.app.DownloadManager

...
var foo = mContext.getSystemService();
`

	SampleVulnerableHSJVM18 = `
import security.KeyStore

...
KeyStore keyStore = KeyStore.getInstance("JKS");
String fileName = System.getProperty("java.home") + 
   "/lib/security/myKeyStore.jks";
 
FileInputStream stream = new FileInputStream(new File(fileName));
keyStore.load( stream, "storeit".toCharArray()); 
`
	SampleSafeHSJVM18 = `
String fileName = System.getProperty("java.home") + 
   "/lib/security/myKeyStore.jks";
 
FileInputStream stream = new FileInputStream(new File(fileName));
`

	SampleVulnerableHSJVM19 = `
import android.app.NotificationManager

...
NotificationManager notificationManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

Uri soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);

NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(getApplicationContext())
    .setSmallIcon(icon)
    .setContentTitle(title)
    .setContentText(message)
    .setSound(soundUri);
notificationManager.notify(0, mBuilder.build());`
	SampleSafeHSJVM19 = `
// Don't send notification for not expose sensitive content.`

	SampleVulnerableHSJVM20 = `
String query = "SELECT * FROM  messages WHERE uid= '"+userInput+"'" ;
Cursor cursor = this.getReadableDatabase().rawQuery(query,null);
`
	SampleSafeHSJVM20 = `
String query = "SELECT * FROM  messages WHERE uid= ?" ;
Cursor cursor = this.getReadableDatabase().rawQuery(query,new String[] {userInput});
`

	SampleVulnerableHSJVM21 = `
import android.database.sqlite;

...
String query = "SELECT * FROM  messages WHERE uid= '"+userInput+"'" ;
Cursor cursor = conn.rawQuery(query,null);
`
	SampleSafeHSJVM21 = `
import android.database.sqlite;

...
String query = "SELECT * FROM  messages WHERE uid= ?" ;
Cursor cursor = conn.rawQuery(query,new String[] {userInput});
`

	SampleVulnerableHSJVM22 = ``
	SampleSafeHSJVM22       = ``

	SampleVulnerableHSJVM23 = ``
	SampleSafeHSJVM23       = ``

	SampleVulnerableHSJVM24 = `
class T {
	void f(String value) {
		byte[] decodedValue = Base64.getDecoder().decode(value);
	}
}
`
	SampleSafeHSJVM24 = `
class T {
	void f() {
		this.decodeSomeRandomValue("value);
		console.log.println("foo.decode");
	}

	void decodeSomeRandomValue(String value) {}
}
`

	SampleVulnerableHSJVM25 = ``
	SampleSafeHSJVM25       = ``

	// Deprecated: Repeated vulnerability, same as HS-JVM-25
	//SampleVulnerableHSJVM26 = ``
	//SampleSafeHSJVM26       = ``

	SampleVulnerableHSJVM27 = ``
	SampleSafeHSJVM27       = ``

	SampleVulnerableHSJVM28 = ``
	SampleSafeHSJVM28       = ``

	SampleVulnerableHSJVM29 = ``
	SampleSafeHSJVM29       = ``

	SampleVulnerableHSJVM30 = ``
	SampleSafeHSJVM30       = ``

	SampleVulnerableHSJVM31 = ``
	SampleSafeHSJVM31       = ``

	SampleVulnerableHSJVM32 = ``
	SampleSafeHSJVM32       = ``

	SampleVulnerableHSJVM33 = ``
	SampleSafeHSJVM33       = ``

	SampleVulnerableHSJVM34 = ``
	SampleSafeHSJVM34       = ``

	SampleVulnerableHSJVM35 = ``
	SampleSafeHSJVM35       = ``

	SampleVulnerableHSJVM36 = ``
	SampleSafeHSJVM36       = ``

	SampleVulnerableHSJVM37 = ``
	SampleSafeHSJVM37       = ``

	SampleVulnerableHSJVM38 = `
class T {
	void f() {
		String input = "test input";
		Base64.getEncoder().encodeToString(input.getBytes());

		Base64 base64 = new Base64();
		String encodedString = new String(base64.encode(input.getBytes()));
	}
}
	`
	SampleSafeHSJVM38 = `
class T {
	void f() {
		obj.addContentType("application/x-www-form-urlencoded")
	}
}
	`
	Sample2SafeHSJVM38 = `
<encoder class="net.logstash.logback.encoder.AccessEventCompositeJsonEncoder">"
<encoder class="net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder">

<encoder>
</encoder>
`

	SampleVulnerableHSJVM39 = ``
	SampleSafeHSJVM39       = ``

	SampleVulnerableHSJVM40 = ``
	SampleSafeHSJVM40       = ``
)
