// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

//nolint:lll multiple regex is not possible broken lines
package regular

import (
	"regexp"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

func NewJavaRegularHiddenElements() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c3e26bb3-a07b-4e1d-881d-0d194f813105",
			Name:        "Hidden elements",
			Description: "Hidden elements in view can be used to hide data from user. But this data can be leaked. For more information checkout the CWE-919 (https://cwe.mitre.org/data/definitions/919.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setVisibility\(View\.GONE\)|setVisibility\(View\.INVISIBLE\)`),
		},
	}
}

func NewJavaRegularWeakCypherBlockMode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "cbf823d8-13f7-45d1-9ab6-b6accfd2414d",
			Name:        "Weak block mode for Cryptographic Hash Function",
			Description: "A weak ECB, (a.k.a 'block mode') was found in one of your Ciphers. Always use a strong, high entropy hash, for example the SHA-512 with salt options. For more information check CWE-327 (https://cwe.mitre.org/data/definitions/327.html), CWE-719 (https://cwe.mitre.org/data/definitions/719.html), CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-780 (https://cwe.mitre.org/data/definitions/780.html) for deeper details on how to fix it.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Cipher\.getInstance\(\s*\".+/ECB/.+\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\"AES.+\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\".+/GCM/.+\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\".+\/CBC\/.*\)`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\"RSA/.+/NoPadding`),
		},
	}
}

func NewJavaRegularWeakHash() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "de9be233-8f65-4e2a-bb6e-8acbc2a4dff3",
			Name:        "Weak Cryptographic Hash Function used",
			Description: "Using a weak CHF pose a threat to your application security since it can be vulnerable to a number of attacks that could lead to data leaking, improper access of features and resources of your infrastructure and even rogue sessions. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getInstance("md4")|getInstance("rc2")|getInstance("rc4")|getInstance("RC4")|getInstance("RC2")|getInstance("MD4")`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*MD5["|']*\)|MessageDigest\.getInstance\(["|']*md5["|']*\)|DigestUtils\.md5\(`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*SHA-?1["|']*\)|MessageDigest\.getInstance\(["|']*sha-?1["|']*\)|DigestUtils\.sha\(|DigestUtils\.getSha1Digest\(`),
			regexp.MustCompile(`getInstance\(["|']rc4["|']\)|getInstance\(["|']RC4["|']\)|getInstance\(["|']RC2["|']\)|getInstance\(["|']rc2["|']\)`),
			regexp.MustCompile(`getInstance\(["|']md4["|']\)|getInstance\(["|']MD4["|']\)|getInstance\(["|']md2["|']\)|getInstance\(["|']MD2["|']\)`),
		},
	}
}

func NewJavaRegularPossibleFileWithVulnerabilityWhenOpen() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fe722822-2c24-4701-9e16-faf848b13aa8",
			Name:        "Possible  File With Vulnerability When Open",
			Description: "The file is World Readable and Writable. Any App can read/write to the file. For more information checkout the CWE-276  (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*3\s*\)`),
		},
	}
}

func NewJavaRegularSensitiveInformationNotEncrypted() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "14b76559-d0b1-4b41-8408-cf28e6f75e0d",
			Name:        "Sensitive Information Not Encrypted",
			Description: "App can write to App Directory. Sensitive Information should be encrypted. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`MODE_PRIVATE|Context\.MODE_PRIVATE`),
		},
	}
}

func NewJavaRegularInsecureRandomNumberGenerator() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1079260f-aea3-4d10-9b14-1a96d7043dad",
			Name:        "Insecure Random Number Generator",
			Description: "The App uses an insecure Random Number Generator. For more information checkout the CWE-330 (https://cwe.mitre.org/data/definitions/330.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`java\.util\.Random`),
			regexp.MustCompile(`scala\.util\.Random`),
		},
	}
}

func NewJavaRegularNoDefaultJavaHash() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a77029ba-1863-4ffd-b2d6-3caf5461ccf6",
			Name:        "No Default Java Hash",
			Description: "This App uses Java Hash Code. It\"s a weak hash function and should never be used in Secure Crypto Implementation. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.hashCode()`),
		},
	}
}

func NewJavaRegularLayoutParamsFlagSecure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bd76384c-9540-4f1f-ba8e-a24e16e21864",
			Name:        "Layout Params Flag Secure",
			Description: "These activities prevent screenshot when they go to background.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`LayoutParams.FLAG_SECURE`),
		},
	}
}

func NewJavaRegularNoUseSQLCipher() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c2e4cd9f-aea9-45e9-8e7a-7f7e893dd9e0",
			Name:        "No use SQL Cipher",
			Description: "This App uses SQL Cipher. But the secret may be hardcoded. For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SQLiteOpenHelper.getWritableDatabase\(`),
		},
	}
}

func NewJavaRegularPreventTapJackingAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "43a692bf-d23b-4137-b652-90c38fd7aca2",
			Name:        "Prevent Tap Jacking Attacks",
			Description: "This app has capabilities to prevent tapjacking attacks. For more information checkout the CWE-1021 (https://cwe.mitre.org/data/definitions/1021.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setFilterTouchesWhenObscured\(true\)`),
		},
	}
}

func NewJavaRegularPreventWriteSensitiveInformationInTmpFile() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2a3f6aef-4fa3-4d40-89c3-a249a28cb17b",
			Name:        "Prevent Write sensitive information in tmp file",
			Description: "App creates temp file. Sensitive information should never be written into a temp file. For more information checkout the CWE-276 (https://cwe.mitre.org/data/definitions/276.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.createTempFile\(`),
		},
	}
}

func NewJavaRegularGetWindowFlagSecure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d34b3ba5-b988-4a0f-9344-467274cd98be",
			Name:        "Get Window Flag Secure",
			Description: "This App has capabilities to prevent against Screenshots from Recent Task History/Now On Tap etc.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getWindow\(.*\)\.(set|add)Flags\(.*\.FLAG_SECURE`),
		},
	}
}

func NewJavaRegularLoadingNativeCode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d0253f59-ae24-4825-bacf-372fd75f1154",
			Name:        "Loading Native Code",
			Description: "Loading Native Code (Shared Library)",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`System\.loadLibrary\(|System\.load\(`),
		},
	}
}

func NewJavaRegularDynamicClassAndDexloading() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a80e1c26-101e-4382-b3af-0d617e4e366f",
			Name:        "Dynamic Class and Dexloading",
			Description: "Dynamic Class and Dexloading",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`dalvik\.system\.DexClassLoader|java\.security\.ClassLoader|java\.net\.URLClassLoader|java\.security\.SecureClassLoader`),
		},
	}
}

func NewJavaRegularCryptoImport() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e647f537-fb3b-40f0-8bbb-f35a414443e0",
			Name:        "Java Crypto import",
			Description: "Java Crypto import",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`javax\.crypto|kalium\.crypto|bouncycastle\.crypto`),
		},
	}
}

func NewJavaRegularStartingService() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "378cfa72-43bf-4e81-ab86-996238fb49c7",
			Name:        "Starting Service",
			Description: "Starting Service",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`startService\(|bindService\(`),
		},
	}
}

func NewJavaRegularSendingBroadcast() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5e6f4999-3461-482b-9047-1b24cf28b9fa",
			Name:        "Sending Broadcast",
			Description: "Sending Broadcast",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(`),
		},
	}
}

func NewJavaRegularLocalFileOperations() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c28d5ca9-5d6a-46ce-9a72-4ed6ba042884",
			Name:        "Local File I/O Operations",
			Description: "Local File I/O Operations",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`OpenFileOutput|getSharedPreferences|SharedPreferences.Editor|getCacheDir|getExternalStorageState|openOrCreateDatabase`),
		},
	}
}

func NewJavaRegularInterProcessCommunication() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7e0001c3-d89d-4da7-8cd3-25dddc6d4157",
			Name:        "Inter Process Communication",
			Description: "Inter Process Communication",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`IRemoteService|IRemoteService\.Stub|IBinder`),
		},
	}
}

func NewJavaRegularDefaultHttpClient() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4455e6d5-4533-49e4-8edc-6efda9fce9c3",
			Name:        "DefaultHttpClient with default constructor is not compatible with TLS 1.2",
			Description: "Upgrade your implementation to use one of the recommended constructs and configure https.protocols JVM option to include TLSv1.2. Use SystemDefaultHttpClient instead. For more information checkout (https://blogs.oracle.com/java-platform-group/diagnosing-tls,-ssl,-and-https)",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSystemDefaultHttpClient\(\)`),
		},
	}
}

func NewJavaRegularWeakSSLContext() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0cc60028-b33b-45e3-9c62-44a0c60ae517",
			Name:        "Weak SSLContext",
			Description: "Upgrade your implementation to the following, and configure https.protocols JVM option to include TLSv1.2:. Use SSLContext.getInstance(\"TLS\"). For more information checkout (https://blogs.oracle.com/java-platform-group/diagnosing-tls,-ssl,-and-https)",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SSLContext\.getInstance\(["|']SSL.*["|']\)`),
		},
	}
}

func NewJavaRegularHostnameVerifierThatAcceptAnySignedCertificates() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5bc8ba32-9022-4ff4-963a-a08ae4a5cae9",
			Name:        "HostnameVerifier that accept any signed certificates",
			Description: "A HostnameVerifier that accept any host are often use because of certificate reuse on many hosts. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`implements\sHostnameVerifier`),
		},
	}
}

func NewJavaRegularURLRewritingMethod() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8c29a16a-8e94-43a9-aa27-4e32a6f0594e",
			Name:        "URL rewriting method",
			Description: "URL rewriting has significant security risks. Since session ID appears in the URL, it may be easily seen by third parties. Session ID in the URL can be disclosed in many ways. For more information checkout the (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.*out.println\(.*(res.encodeURL\(HttpUtils.getRequestURL\(.*\).toString\(\)).*\)`),
		},
	}
}

func NewJavaRegularDisablingHTMLEscaping() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a4df3c73-70bf-4594-ba37-43aed3df8509",
			Name:        "Disabling HTML escaping",
			Description: "Disabling HTML escaping put the application at risk for Cross-Site Scripting (XSS). For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`add\(new Label\(.*\).setEscapeModelStrings\(false\)\)`),
		},
	}
}

func NewJavaRegularOverlyPermissiveCORSPolicy() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8f10b6ba-065d-4e14-b3b9-ec231884b086",
			Name:        "Overly permissive CORS policy",
			Description: "A web server defines which other domains are allowed to access its domain using cross-origin requests. However, caution should be taken when defining the header because an overly permissive CORS policy will allow a malicious application to communicate with the victim application in an inappropriate way, leading to spoofing, data theft, relay and other attacks. For more information checkout the (https://fetch.spec.whatwg.org/) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.addHeader\("Access-Control-Allow-Origin", "\*"\)`),
		},
	}
}

func NewJavaRegularSQLInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "22e307e8-af07-4397-a9bf-232bad45fa52",
			Name:        "SQL Injection",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createQuery\(.?((.*|\n)*)?)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?)))`),
			// regexp.MustCompile(`\.encodeForSQL\(`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewJavaRegularSQLInjectionWithTurbine() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8192e0eb-d9c7-4718-a80d-40bf2ebbcfab",
			Name:        "SQL Injection With Turbine",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Turbine API provide a DSL to build query with Java code. Alternatively to prepare statements, each parameter can be escaped manually. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(BasePeer\.)?(executeQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.encodeForSQL\(`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewJavaRegularSQLInjectionWithHibernate() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "99ce8a42-71aa-43f6-b247-28891f862c9d",
			Name:        "SQL Injection With Hibernate",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, Hibernate Criteria can be used. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory and checkout the CWE-564 (https://cwe.mitre.org/data/definitions/564.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(openSession\(\))?(\.)(createQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setString|\.setInteger`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewJavaRegularSQLInjectionWithJDO() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6d93be06-de01-4522-91b5-648d5d11fcad",
			Name:        "SQL Injection With JDO",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(getPM\(\))?(\.)(newQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.declareParameters`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewJavaRegularSQLInjectionWithJPA() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "477f2d07-8b1a-4b14-971d-e476ebcb9002",
			Name:        "SQL Injection With JPA",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(getEM\(\))?(\.)(createQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setParameter`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewJavaRegularSQLInjectionWithSpringJDBC() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "772b4a13-5fb1-4deb-8fcc-4cb39bfb3e9f",
			Name:        "SQL Injection Spring JDBC",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(JdbcTemplate\(\))?(\.)(queryForObject\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setParameter`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewJavaRegularSQLInjectionWithJDBC() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bfa5c53d-2ea2-4499-bf82-daaf4cca4400",
			Name:        "SQL Injection JDBC",
			Description: "The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createStatement\(\))?(\.)(executeQuery\(.?((.*|\n)*)?((select|SELECT)|(update|UPDATE)|(insert|INSERT)|(delete|DELETE))((.*|\n)*)?((=(\s?)(["|']*)(\s?)(\+))|(=(\s?)\%.(["|']*)(.*?|\n?)(\,?))))`),
			// regexp.MustCompile(`\.setParameter`), // Commented because is necessary not contains this code for get an vulnerability
		},
	}
}

func NewJavaRegularLDAPInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2820379a-5322-4131-9f2d-7e3ad1d4aed8",
			Name:        "Potential LDAP Injection",
			Description: "Just like SQL, all inputs passed to an LDAP query need to be passed in safely. Unfortunately, LDAP doesn't have prepared statement interfaces like SQL. Therefore, the primary defense against LDAP injection is strong input validation of any untrusted data before including it in an LDAP query. For more information checkout the CWE-90 (https://cwe.mitre.org/data/definitions/90.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(search\(["|'](((.*|\n))*)(\+.*\+.*)["|']\))|(search\(.*,.*,.*,new SearchControls\()`),
		},
	}
}

func NewJavaRegularPotentialExternalControl() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "357b9de7-6d22-4e5f-9bd6-cfe69431f319",
			Name:        "Potential external control of configuration",
			Description: "Allowing external control of system settings can disrupt service or cause an application to behave in unexpected, and potentially malicious ways. An attacker could cause an error by providing a nonexistent catalog name or connect to an unauthorized portion of the database. For more information checkout the CWE-15 (https://cwe.mitre.org/data/definitions/15.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setCatalog\(.*\.getParameter`),
		},
	}
}

func NewJavaRegularBadHexadecimalConcatenation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e6bfb8da-3680-497e-9652-63d6913b791d",
			Name:        "Bad hexadecimal concatenation",
			Description: "When converting a byte array containing a hash signature to a human readable string, a conversion mistake can be made if the array is read byte by byte. The following sample illustrates the use of the method Integer.toHexString() which will trim any leading zeroes from each byte of the computed hash value. For more information checkout the CWE-704 (https://cwe.mitre.org/data/definitions/704.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`&\s[0xFF]`),
		},
	}
}

func NewJavaRegularNullCipherInsecure() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1c11c767-15d9-4030-935b-0905b7607f37",
			Name:        "NullCipher is insecure",
			Description: "The NullCipher is rarely used intentionally in production applications. It implements the Cipher interface by returning ciphertext identical to the supplied plaintext. In a few contexts, such as testing, a NullCipher may be appropriate. For more information checkout the CWE-704 (https://cwe.mitre.org/data/definitions/704.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NullCipher\(`),
		},
	}
}

func NewJavaRegularUnsafeHashEquals() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4dad1120-f1bd-4b26-8561-699a7d61af84",
			Name:        "Unsafe hash equals",
			Description: "An attacker might be able to detect the value of the secret hash due to the exposure of comparison timing. When the functions Arrays.equals() or String.equals() are called, they will exit earlier if fewer bytes are matched. For more information checkout the CWE-704 (https://cwe.mitre.org/data/definitions/704.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\.equals\()(.*)(hash|Hash)`),
		},
	}
}

func NewJavaRegularUnvalidatedRedirect() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "869b7ff4-54b6-414f-9524-3eb4d5700801",
			Name:        "Unvalidated Redirect",
			Description: "Unvalidated redirects occur when an application redirects a user to a destination URL specified by a user supplied parameter that is not validated. Such vulnerabilities can be used to facilitate phishing attacks. For more information checkout the CWE-601 (https://cwe.mitre.org/data/definitions/601.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`sendRedirect\(.*.getParameter\(.*\)\)`),
		},
	}
}

func NewJavaRegularRequestMappingMethodsNotPublic() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c6418f44-3424-44fd-b49e-6af5dd0dc219",
			Name:        "@RequestMapping methods should be public",
			Description: "A method with a @RequestMapping annotation part of a class annotated with @Controller (directly or indirectly through a meta annotation - @RestController from Spring Boot is a good example) will be called to handle matching web requests. That will happen even if the method is private, because Spring invokes such methods via reflection, without checking visibility. For more information checkout the OWASAP:A6 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration) advisory",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`RequestMapping\((.*\n)(.*)private`),
		},
	}
}

func NewJavaRegularLDAPDeserializationNotDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "73072f1e-fd29-424c-938a-f233e589d23d",
			Name:        "LDAP deserialization should be disabled",
			Description: "JNDI supports the deserialization of objects from LDAP directories, which is fundamentally insecure and can lead to remote code execution. This rule raises an issue when an LDAP search query is executed with SearchControls configured to allow deserialization. For more information checkout the CWE-502 (https://cwe.mitre.org/data/definitions/502.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`SearchControls\(((.*|\n)*)true((.*|\n)*)\)`),
		},
	}
}

func NewJavaRegularDatabasesPasswordNotProtected() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "71dd0c28-bed7-4c34-ac50-94a9ac3b8b5b",
			Name:        "Databases should be password-protected",
			Description: "Databases should always be password protected. The use of a database connection with an empty password is a clear indication of a database that is not protected. For more information checkout the CWE-521 (https://cwe.mitre.org/data/definitions/521.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.getConnection\(['|"]jdbc`),
		},
	}
}
