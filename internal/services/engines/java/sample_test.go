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

package java

const (
	SampleVulnerableHSJAVA1 = `
public class Foo {
	void fn(String input) {
		XMLReader reader = XMLReaderFactory.createXMLReader();
		reader.parse(input)
	}
}
	`

	SampleSafeHSJAVA1 = `
public class Foo {
	void bar() {
		XMLReader reader = XMLReaderFactory.createXMLReader();
		reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		reader.setContentHandler(customHandler);
		
		reader.parse(new InputSource(inputStream));
	}
}
	`

	Sample2SafeHSJAVA1 = `
public class Foo {
	void bar() {
		XMLReader reader = XMLReaderFactory.createXMLReader();
		reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		reader.setContentHandler(customHandler);
		
		reader.parse(new InputSource(inputStream));
	}
}
	`

	SampleVulnerableHSJAVA2 = `
public class Foo {
	public void parseXML(InputStream input) throws XMLStreamException {
		XMLInputFactory factory = XMLInputFactory.newFactory();
		XMLStreamReader reader = factory.createXMLStreamReader(input);
	}
}
	`

	SampleSafeHSJAVA2 = `
public class Foo {
	public void parseXML(InputStream input) throws XMLStreamException {
		XMLInputFactory factory = XMLInputFactory.newFactory();
		factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		XMLStreamReader reader = factory.createXMLStreamReader(input);
	}
}
	`

	Sample2SafeHSJAVA2 = `
public class Foo {
	public void parseXML(InputStream input) throws XMLStreamException {
		XMLInputFactory factory = XMLInputFactory.newFactory();
		factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		XMLStreamReader reader = factory.createXMLStreamReader(input);
	}
}
	`

	SampleVulnerableHSJAVA3 = `
public class Foo {
	void bar() {
		DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		
		Document doc = db.parse(input);
	}
}
	`

	SampleSafeHSJAVA3 = `
public class Foo {
	void bar() {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		
		Document doc = db.parse(input);
	}
}
	`

	Sample2SafeHSJAVA3 = `
public class Foo {
	void bar() {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		
		Document doc = db.parse(input);
	}
}
	`

	SampleVulnerableHSJAVA4 = `
public class Foo {
	void bar() {
		SAXParser parser = SAXParserFactory.newInstance().newSAXParser();
		
		parser.parse(inputStream, customHandler);
	}
}
	`

	SampleSafeHSJAVA4 = `
public class Foo {
	void bar() {
		SAXParserFactory spf = SAXParserFactory.newInstance();

		spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

		SAXParser parser = spf.newSAXParser();
	
		parser.parse(inputStream, customHandler);
	}
}
	`

	Sample2SafeHSJAVA4 = `
public class Foo {
	void bar() {
		SAXParserFactory spf = SAXParserFactory.newInstance();
		spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		SAXParser parser = spf.newSAXParser();
		
		parser.parse(inputStream, customHandler);
	}
}
	`

	SampleVulnerableHSJAVA5 = `
public class Foo {
	public void Bar() {
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.transform(input, result);
	}
}
	`

	SampleSafeHSJAVA5 = `
public class Foo {
	public void Bar() {
		TransformerFactory factory = TransformerFactory.newInstance();
		factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		
		Transformer transformer = factory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		
		transformer.transform(input, result);
	}
}
	`

	Sample2SafeHSJAVA5 = `
public class Foo {
	public void Bar() {
		TransformerFactory factory = TransformerFactory.newInstance();
		factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
		factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all");
		
		Transformer transformer = factory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		
		transformer.transform(input, result);
	}
}
	`

	SampleVulnerableHSJAVA7 = `
public class Foo {
	public void Bar() {
		SAXReader xmlReader = new SAXReader();
		Document document = reader.read(url);
	}
}
	`

	SampleSafeHSJAVA7 = `
public class Foo {
	public void Bar() {
		SAXReader xmlReader = new SAXReader();
		xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		Document document = reader.read(url);
	}
}
	`

	SampleVulnerableHSJAVA8 = `
public class Foo {
	public void Bar() {
		SAXBuilder builder = new SAXBuilder();
		Document d = builder.build("xpath.xml");
	}
}
	`

	SampleSafeHSJAVA8 = `
public class Foo {
	public void Bar() {
		SAXBuilder builder = new SAXBuilder();
		builder.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		builder.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		Document d = builder.build("xpath.xml");
	}
}
	`

	SampleVulnerableHSJAVA9 = `
import javax.net.ssl

public class Foo {
	public HttpClient getNewHttpClient() {
		try {
			KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(null, null);
	
			MySSLSocketFactory sf = new MySSLSocketFactory(trustStore);
			sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

			return new DefaultHttpClient(ccm, params);
		} catch (Exception e) {
			return new DefaultHttpClient();
		}
	}
}
	`

	SampleSafeHSJAVA9 = `
import javax.net.ssl

public class Foo {
	public HttpClient getNewHttpClient() {
		try {
			KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(null, null);
	
			MySSLSocketFactory sf = new MySSLSocketFactory(trustStore);

			return new DefaultHttpClient(ccm, params);
		} catch (Exception e) {
			return new DefaultHttpClient();
		}
	}
}
	`

	SampleVulnerableHSJAVA10 = `
MyProprietaryMessageDigest extends MessageDigest {
	@Override
	protected byte[] engineDigest() {
	}
}
	`

	SampleSafeHSJAVA10 = `
public class Foo {
	public void Bar() {
		MessageDigest sha256Digest = MessageDigest.getInstance("SHA256");
		sha256Digest.update(password.getBytes());
	}
}
	`

	SampleVulnerableHSJAVA11 = `
class TrustAllManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        //Trust any client connecting (no certificate validation)
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        //Trust any remote server (no certificate validation)
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}
	`

	SampleSafeHSJAVA11 = `
public class Foo {
	public void Bar() {
		KeyStore ks = //Load keystore containing the certificates trusted
		
		SSLContext sc = SSLContext.getInstance("TLS");
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(ks);
		
		sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(),null);
	}
}
	`

	SampleVulnerableHSJAVA12 = `
public class Foo {
	public void Bar() {
		URL url = new URL("https://example.org/");
		HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
		urlConnection.setHostnameVerifier(new HostnameVerifier() {
		  @Override
		  public boolean verify(String requestedHost, SSLSession remoteServerSession) {
			return true;
		  }
		});
		InputStream in = urlConnection.getInputStream();
	}
}
	`

	SampleSafeHSJAVA12 = `
public class Foo {
	public void Bar() {
		URL url = new URL("https://example.org/");
		HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
		InputStream in = urlConnection.getInputStream();
	}
}
	`

	SampleVulnerableHSJAVA13 = `
public class Foo {
	public void Bar() {
		Email email = new SimpleEmail();
		email.setHostName("smtp.servermail.com");
		email.setSmtpPort(465);
		email.setAuthenticator(new DefaultAuthenticator(username, password));
		email.setSSLOnConnect(true);
		email.setFrom("user@gmail.com");
		email.setSubject("TestMail");
		email.setMsg("This is a test mail ... :-)");
		email.addTo("foo@bar.com");
		email.send();
	}
}
	`

	SampleSafeHSJAVA13 = `
public class Foo {
	public void Bar() {
		Email email = new SimpleEmail();
		email.setHostName("smtp.servermail.com");
		email.setSmtpPort(465);
		email.setAuthenticator(new DefaultAuthenticator(username, password));
		email.setSSLOnConnect(true);
		email.setFrom("user@gmail.com");
		email.setSubject("TestMail");
		email.setSSLCheckServerIdentity(true);
		email.setMsg("This is a test mail ... :-)");
		email.addTo("foo@bar.com");
		email.send();
	}
}
	`

	SampleVulnerableHSJAVA14 = `
public class Foo {
	public void Bar() {
		Properties props = new Properties();
		props.put("mail.smtp.host", "smtp.gmail.com");
		props.put("mail.smtp.socketFactory.port", "465");
		props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.port", "465");
		Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
		  protected PasswordAuthentication getPasswordAuthentication() {
			return new PasswordAuthentication("username@gmail.com", "password");
		  }
		});
	}
}
	`

	SampleSafeHSJAVA14 = `
public class Foo {
	public void Bar() {
		Properties props = new Properties();
		props.put("mail.smtp.host", "smtp.gmail.com");
		props.put("mail.smtp.socketFactory.port", "465");
		props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.port", "465");
		props.put("mail.smtp.ssl.checkserveridentity", true); // Compliant
		Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
		  protected PasswordAuthentication getPasswordAuthentication() {
			return new PasswordAuthentication("username@gmail.com", "password");
		  }
		});
	}
}
	`

	SampleVulnerableHSJAVA18 = `
import android.webkit.WebView;

public class Foo {
	public void Bar() {
		WebView.loadUrl("file://"+Environment.getExternalStorageDirectory().getAbsolutePath()+"dangerZone.html");
	}
}
	`

	SampleSafeHSJAVA18 = `
import android.webkit.WebView;

public class Foo {
	public void Bar() {
			myWebView.loadUrl("https://www.example.com");
		});
	}
}
	`

	SampleVulnerableHSJAVA19 = `
package com.example.root.vulnerableapp;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundler;
import android.webkit.WebView;
import android.webkit.WebSettings;

public class MainActivity extends AppCompatActivity {
	@Override
	protected void onCreate(Bundler savedInstanceState) {
		super.onCreate(savedInstanceState);
		set.ContentView(R.layout.activity_main);
		
		WebView myWEbView = (WebView) findViewById(R.id.webview);
		WebSettings webSettings = myWebView.getSettings();
		webSettings.setJavaScriptEnabled(true);

		myWebView.addJavascriptInterface(new WebAppInterface(this), "Android");
		myWebView.loadUrl("http://10.0.0.2");
	}
}
	`

	SampleSafeHSJAVA19 = `
package com.example.root.vulnerableapp;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundler;
import android.webkit.WebView;
import android.webkit.WebSettings;

public class MainActivity extends AppCompatActivity {
	@Override
	protected void onCreate(Bundler savedInstanceState) {
		super.onCreate(savedInstanceState);
		set.ContentView(R.layout.activity_main);
		
		WebView myWEbView = (WebView) findViewById(R.id.webview);
		WebSettings webSettings = myWebView.getSettings();

		myWebView.loadUrl("http://10.0.0.2");
	}
}
	`

	SampleVulnerableHSJAVA22 = `
public class Foo {
	Java.perform(function() {
	   var Webview = Java.use("android.webkit.WebView")
	   Webview.onTouchEvent.overload("android.view.MotionEvent").implementation = 
	   function(touchEvent) {
		 this.setWebContentsDebuggingEnabled(true);
		 this.onTouchEvent.overload("android.view.MotionEvent").call(this, touchEvent);
	   }
	});
}
	`

	SampleSafeHSJAVA22 = `
public class Foo {
	Java.perform(function() {
	   var Webview = Java.use("android.webkit.WebView")
	   Webview.onTouchEvent.overload("android.view.MotionEvent").implementation = 
	   function(touchEvent) {
		 this.setWebContentsDebuggingEnabled(false);
		 this.onTouchEvent.overload("android.view.MotionEvent").call(this, touchEvent);
	   }
	});
}
	`

	SampleVulnerableHSJAVA23 = `
import android.app.Service;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.IBinder;

import java.util.List;

public class ClipboardWatcherService extends Service {

    public static final StringBuilder log = new StringBuilder("--- STUFF THAT I SENT TO MY SERVER ---\n\n");
    public static boolean serviceIsRunning = false;

    private ClipboardManager.OnPrimaryClipChangedListener listener = new ClipboardManager.OnPrimaryClipChangedListener() {
        public void onPrimaryClipChanged() {
            performClipboardCheck();
        }
    };

    @Override
    public void onCreate() {
        ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).addPrimaryClipChangedListener(listener);
        checkForPasswordManager();
        serviceIsRunning = true;
    }
}
	`

	SampleSafeHSJAVA23 = `
public class Foo {
	@Test
	public void shouldHavePrimaryClipIfText() {
	 clipboardManager.setText("BLARG?");
	 assertThat(clipboardManager.hasPrimaryClip()).isTrue();
	}
}
	`

	SampleVulnerableHSJAVA24 = `
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;

public class Foo {
    public static void setText(Context context, CharSequence text) {
        if (isNew()) {
            instance(context);
            ClipData clip = ClipData.newPlainText("simple text", text);
            clipboardManager.setPrimaryClip(clip);
        } else {
            instance(context);
            clipboardManager.setText(text);
        }
    }
}
`

	SampleSafeHSJAVA24 = `
public class Foo {
	@Test
	public void shouldHavePrimaryClipIfText() {
	 clipboardManager.setText("BLARG?");
	 assertThat(clipboardManager.hasPrimaryClip()).isTrue();
	}
}
`

	SampleVulnerableHSJAVA25 = `
public class Foo {
	  @Override
	  public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
		handler.proceed();
	  }
}
`

	SampleSafeHSJAVA25 = `
public class Foo {
	  @Override
	  public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
		System.out.println(error);
	  }
}
`

	SampleVulnerableHSJAVA26 = `
public void findUser(String parameterInput) {
    SqlUtil.execQuery("select * from UserEntity where id = " + parameterInput);
}
`

	SampleSafeHSJAVA26 = `
public void findUser() {
    SqlUtil.execQuery("select * from UserEntity where id = 1");
}
`

	SampleVulnerableHSJAVA28 = `
package org.thoughtcrime.ssl.pinning;

	public static HttpClient getPinnedHttpClient(Context context, String[] pins) {
		try {
			SchemeRegistry schemeRegistry = new SchemeRegistry();
			schemeRegistry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
			schemeRegistry.register(new Scheme("https", new PinningSSLSocketFactory(context, pins, 0), 443));
			 
			HttpParams httpParams                     = new BasicHttpParams();
			ClientConnectionManager connectionManager = new ThreadSafeClientConnManager(httpParams, schemeRegistry);
			return new DefaultHttpClient(connectionManager, httpParams);
		} catch (UnrecoverableKeyException e) {
		throw new AssertionError(e);
		} catch (KeyManagementException e) {
		throw new AssertionError(e);
		} catch (NoSuchAlgorithmException e) {
		throw new AssertionError(e);
		} catch (KeyStoreException e) {
		throw new AssertionError(e);
		}
	}
`

	SampleSafeHSJAVA28 = `
  public static HttpsURLConnection getPinnedHttpsURLConnection(Context context, String[] pins, URL url)
      throws IOException
  {
    try {
      if (!url.getProtocol().equals("https")) {
        throw new IllegalArgumentException("Attempt to construct pinned non-https connection!");
      }
      TrustManager[] trustManagers = new TrustManager[1];
      trustManagers[0]             = new PinningTrustManager(SystemKeyStore.getInstance(context), pins, 0);

      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, trustManagers, null);

      HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
      urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());

      return urlConnection;
    } catch (NoSuchAlgorithmException nsae) {
      throw new AssertionError(nsae);
    } catch (KeyManagementException e) {
      throw new AssertionError(e);
    }
  }
`

	SampleVulnerableHSJAVA111 = `
public class Foo {
	public void Bar() {
		MessageDigest md5Digest = MessageDigest.getInstance("MD5");
		md5Digest.update(password.getBytes());
		byte[] hashValue = md5Digest.digest();
	}
}
`

	Sample2VulnerableHSJAVA111 = `
public class Foo {
	public void Bar() {
		byte[] hashValue = DigestUtils.getMd5Digest().digest(password.getBytes());
	}
}
`

	Sample3VulnerableHSJAVA111 = `
public class Foo {
	public void Bar() {
		MessageDigest sha1Digest = MessageDigest.getInstance("SHA1");
		sha1Digest.update(password.getBytes());
		byte[] hashValue = sha1Digest.digest();
	}
}
`

	Sample4VulnerableHSJAVA111 = `
public class Foo {
	public void Bar() {
		byte[] hashValue = DigestUtils.getSha1Digest().digest(password.getBytes());
	}
}
`

	SampleSafeHSJAVA111 = `
public class Foo {
	public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
		gen.init(password.getBytes("UTF-8"), salt.getBytes(), 4096);
		return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
	}
}
`

	Sample2SafeHSJAVA111 = `
public class Foo {
	public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 4096, 256 * 8);
		SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		return f.generateSecret(spec).getEncoded();
	}
}
`

	Sample3SafeHSJAVA111 = `
public class Foo {
	public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
		gen.init(password.getBytes("UTF-8"), salt.getBytes(), 4096);
		return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
	}
}
`

	Sample4SafeHSJAVA111 = `
public class Foo {
	public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 4096, 256 * 8);
		SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		return f.generateSecret(spec).getEncoded();
	}
}
`

	SampleVulnerableHSJAVA134 = `
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.sql.DataSource;

public class VulnerableCodeSQLInjection134 {

    public void printResults(DataSource ds, String field01) throws SQLException {
        try (
                var con = ds.getConnection();
                var pstmt = con.prepareStatement("select * from mytable where field01 = '" + field01 + "'");
                var rs = pstmt.executeQuery()) {
            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
        }
    }
}
`

	SampleSafeHSJAVA134 = `
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.sql.DataSource;

public class VulnerableCodeSQLInjection134 {

    public void printResults(DataSource ds, String field01) throws SQLException {
        try {
            var con = ds.getConnection();
            var pstmt = con.prepareStatement("select * from mytable where field01 = ? ");
            pstmt.setString(1,field01);
            var rs = pstmt.executeQuery();
            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
        }
    }
}
`

	SampleVulnerableHSJAVA144 = `
public class Foo {
	public void Bar() {
		Cipher doNothingCihper = new NullCipher();

		byte[] cipherText = c.doFinal(plainText);
	}
}
`

	SampleVulnerableHSJAVA145 = `
public class Foo {
	public void Bar() {
		String actualHash = 12345

		if(userInput.equals(actualHash)) {

		}
	}
}
`

	SampleSafeHSJAVA145 = `
public class Foo {
	public void Bar() {
		String actualHash = 12345

		if(MessageDigest.isEqual(userInput.getBytes(),actualHash.getBytes())) {

		}
	}
}
`

	SampleVulnerableHSJAVA146 = `
public class Foo {
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
	  resp.sendRedirect(req.getParameter("url"));
	}
}

`

	SampleSafeHSJAVA146 = `
public class Foo {
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
	  String location = req.getParameter("url");
	
	  List<String> allowedHosts = new ArrayList<String>();
	  allowedUrls.add("https://www.domain1.com/");
	  allowedUrls.add("https://www.domain2.com/");
	
	  if (allowedUrls.contains(location))
		resp.sendRedirect(location);
	}
}
`

	SampleVulnerableHSJAVA147 = `
public class Foo {
    @RequestMapping("/test")
    private void test() {
    }
}

`

	SampleSafeHSJAVA147 = `
public class Foo {
    @RequestMapping("/test")
    public void test() {
    }
}
`

	SampleVulnerableHSJAVA148 = `
public class Foo {
	public void Bar() {
		DirContext ctx = new InitialDirContext();
		
		ctx.search(query, filter,new SearchControls(scope, countLimit, timeLimit, attributes,true, deref));
	}
}

`

	SampleSafeHSJAVA148 = `
public class Foo {
	public void Bar() {
		DirContext ctx = new InitialDirContext();
		
		ctx.search(query, filter, new SearchControls(scope, countLimit, timeLimit, attributes, false, deref));
	}
}
`

	SampleVulnerableHSJAVA149 = `
public class Foo {
	public void Bar() {
		Connection conn = DriverManager.getConnection("jdbc:derby:memory:myDB;create=true", "login", "");
	}
}

`

	SampleSafeHSJAVA149 = `
public class Foo {
	public void Bar() {
		String password = System.getProperty("database.password");
		Connection conn = DriverManager.getConnection("jdbc:derby:memory:myDB;create=true", "login", password);
	}
}
`
)
