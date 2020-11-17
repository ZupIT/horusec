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

func NewCsharpRegularNoLogSensitiveInformationInConsole() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "71755d83-d536-4839-8997-6b611b319678",
			Name:        "No Log Sensitive Information in console",
			Description: "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`((Log|log).*\.(V|D|I|W|E|F|S))|(Console.Write)`),
		},
	}
}

func NewCsharpRegularCrossSiteScripting() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "899e67a9-72b6-413f-9743-b9a9a7a742c1",
			Name:        "Cross-Site Scripting (XSS)",
			Description: "A potential XSS was found. The endpoint returns a variable from the client input that has not been encoded. To protect against stored XSS attacks, make sure any dynamic content coming from user or data store cannot be used to inject JavaScript on a page. Most modern frameworks will escape dynamic content by default automatically (Razor for example) or by using special syntax (<%: content %>, <%= HttpUtility.HtmlEncode(content) %>). For more information access: (https://security-code-scan.github.io/#SCS0029).",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[HttpGet\(.*\)\]|\[HttpPost\(.*\)\]|\[HttpPut\(.*\)\]|\[HttpDelete\(.*\)\])(([^H]|H[^t]|Ht[^t]|Htt[^p]|Http[^U]|HttpU[^t]|HttpUt[^i]|HttpUti[^l]|HttpUtil[^i]|HttpUtili[^t]|HttpUtilit[^y]|HttpUtility[^.]|HttpUtility\.H[^t]|HttpUtility\.Ht[^m]|HttpUtility\.Htm[^l]|HttpUtility\.Html[^E]|HttpUtility\.HtmlE[^n]|HttpUtility\.HtmlEn[^c]|HttpUtility\.HtmlEnc[^o]|HttpUtility\.HtmlEnco[^d]|HttpUtility\.HtmlEncod[^e])*)(})`),
		},
	}
}

func NewCsharpRegularOutputCacheConflict() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5fc0eefc-31b3-4d07-8d97-37834aff963e",
			Name:        "OutputCache Conflict",
			Description: "Having the annotation [OutputCache] will disable the annotation [Authorize] for the requests following the first one. For more information access: (https://security-code-scan.github.io/#SCS0019).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[Authorize\])(.*|\n)*(\[OutputCache\])`),
		},
	}
}

func NewCsharpRegularOpenRedirect() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "eb1e2fb1-38f0-419f-b6f8-d9dd78d9cb6d",
			Name:        "Open Redirect",
			Description: "Your site may be used in phishing attacks. An attacker may craft a trustworthy looking link to your site redirecting a victim to a similar looking malicious site: 'http://yourdomain.com?redirect=https://urdomain.com/login'. For more information access: (https://security-code-scan.github.io/#SCS0027).",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`String.IsNullOrEmpty.*\n?.*{?\n?.*return\sRedirect\(.*\);`),
		},
	}
}

func NewCsharpRegularRequestValidationDisabledAttribute() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "bd2e5131-5afa-4063-a303-7d5cb2696265",
			Name:        "Request Validation Disabled (Attribute)",
			Description: "Request validation is disabled. Request validation allows the filtering of some XSS patterns submitted to the application. For more information access: (https://security-code-scan.github.io/#SCS0017).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\[ValidateInput\(false\)\]`),
		},
	}
}

func NewCsharpRegularSQLInjectionOLEDB() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2586df5f-1302-48b7-b5ab-780bccf16963",
			Name:        "SQL Injection OLE DB",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0020).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new OleDbConnection\(.*\))(([^P]|P[^a]|Pa[^r]|Par[^a]|Para[^m]|Param[^e]|Parame[^t]|Paramet[^e]|Paramete[^r]|Parameter[^s]|Parameters[^.]|Parameters\.[^A]|Parameters\.A[^d]|Parameters\.Ad[^d])*)(\.ExecuteReader\(.*\))`),
		},
	}
}

func NewCsharpRegularRequestValidationDisabledConfigurationFile() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "055817b7-8a0c-4024-b170-e96ad4fe32a0",
			Name:        "Request Validation Disabled (Configuration File)",
			Description: "The validateRequest which provides additional protection against XSS is disabled in configuration file. For more information access: (https://security-code-scan.github.io/#SCS0017) or (https://cwe.mitre.org/data/definitions/20.html).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`validateRequest\s*=\s*['|"]false['|"]`),
		},
	}
}

func NewCsharpRegularSQLInjectionMsSQLDataProvider() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c418d2d0-1a99-4f44-8e22-8af3c56a3f60",
			Name:        "SQL Injection MsSQL Data Provider",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0026).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new SqlCommand\(.*\))(([^P]|P[^a]|Pa[^r]|Par[^a]|Para[^m]|Param[^e]|Parame[^t]|Paramet[^e]|Paramete[^r]|Parameter[^s]|Parameters[^.]|Parameters\.[^A]|Parameters\.A[^d]|Parameters\.Ad[^d]|Parameters\.Add[^W]|Parameters\.AddW[^i]|Parameters\.AddWi[^t]|Parameters\.AddWit[^h]|Parameters\.AddWith[^V]|Parameters\.AddWithV[^a]|Parameters\.AddWithVa[^l]|Parameters\.AddWithVal[^u]|Parameters\.AddWithValu[^e])*)(Open\(\)|ExecuteReader\(\))`),
		},
	}
}

func NewCsharpRegularRequestValidationIsEnabledOnlyForPages() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "54a8ac1a-83df-4d7d-97de-e0901080b451",
			Name:        "Request validation is enabled only for pages",
			Description: "The requestValidationMode which provides additional protection against XSS is enabled only for pages, not for all HTTP requests in configuration file. For more information access: (https://security-code-scan.github.io/#SCS0030).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`requestValidationMode\s*=\s*['|"][0-3][^\d].*['|"]`),
		},
	}
}

func NewCsharpRegularSQLInjectionEntityFramework() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ae6164f0-e336-4fd1-9337-1214afe24972",
			Name:        "SQL Injection Entity Framework",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database, please use SqlParameter to create query with parameters. For more information access: (https://security-code-scan.github.io/#SCS0035) or (https://cwe.mitre.org/data/definitions/89.html) .",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(Database\.ExecuteSqlCommand)(([^S]|S[^q]|Sq[^l]|Sql[^P]|SqlP[^a]|SqlPa[^r]|SqlPar[^a]|SqlPara[^m]|SqlParam[^e]|SqlParame[^t]|SqlParamet[^e]|SqlParamete[^r])*)(\);)`),
		},
	}
}

func NewCsharpRegularViewStateNotEncrypted() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "25926a6c-b546-482d-81ee-8d82cd6919d5",
			Name:        "View State Not Encrypted",
			Description: "The viewStateEncryptionMode is not set to Always in configuration file. Web Forms controls use hidden base64 encoded fields to store state information. If sensitive information is stored there it may be leaked to the client side. For more information access: (https://security-code-scan.github.io/#SCS0023) or (https://cwe.mitre.org/data/definitions/200.html).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`viewStateEncryptionMode\s*=\s*['|"](Auto|Never)['|"]`),
		},
	}
}

func NewCsharpRegularSQLInjectionNhibernate() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5c53c81e-5125-45a1-8b2c-bfa2b50a9cc5",
			Name:        "SQL Injection Nhibernate",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0037).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(CreateSQLQuery)(([^S]|S[^e]|Se[^t]|Set[^P]|SetP[^a]|SetPa[^r]|SetPar[^a]|SetPara[^m]|SetParam[^e]|SetParame[^t]|SetParamet[^e]|SetParamete[^r])*)(\);)`),
		},
	}
}

func NewCsharpRegularViewStateMacDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "cbd6b77e-b4d5-4507-8835-3262faf669e4",
			Name:        "View State MAC Disabled",
			Description: "The enableViewStateMac is disabled in configuration file. (This feature cannot be disabled starting .NET 4.5.1). The view state could be altered by an attacker. For more information access: (https://security-code-scan.github.io/#SCS0024) or (https://cwe.mitre.org/data/definitions/807.html).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`enableViewStateMac\s*=\s*['|"]false['|"]`),
		},
	}
}

func NewCsharpRegularSQLInjectionNpgsql() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4a5d6ab4-ee09-4b39-b6b5-1f485c15e041",
			Name:        "SQL Injection Npgsql",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0039).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(NpgsqlCommand\(.*\))(([^P]|P[^a]|Pa[^r]|Par[^a]|Para[^m]|Param[^e]|Parame[^t]|Paramet[^e]|Paramete[^r]|Parameter[^s]|Parameters[^.]|Parameters\.[^A]|Parameters\.A[^d]|Parameters\.Ad[^d]|Parameters\.Add[^W]|Parameters\.AddW[^i]|Parameters\.AddWi[^t]|Parameters\.AddWit[^h]|Parameters\.AddWith[^V]|Parameters\.AddWithV[^a]|Parameters\.AddWithVa[^l]|Parameters\.AddWithVal[^u]|Parameters\.AddWithValu[^e])*)(ExecuteNonQuery\(.*\)|ExecuteReader\(.*\))`),
		},
	}
}

func NewCsharpRegularCertificateValidationDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c83a6f75-898e-4621-be87-b9ef0ce85ce7",
			Name:        "Certificate Validation Disabled",
			Description: "Disabling certificate validation is often used to connect easily to a host that is not signed by a root certificate authority. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information access: (https://security-code-scan.github.io/#SCS0004).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ServicePointManager\.ServerCertificateValidationCallback \+= (.*) => true;`),
		},
	}
}

func NewCsharpRegularWeakCipherAlgorithm() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "654e89b5-714c-4006-bd08-345c60e5ce00",
			Name:        "Weak cipher algorithm",
			Description: "Broken or deprecated ciphers have typically known weakness. A attacker might be able to brute force the secret key use for the encryption. The confidentiality and integrity of the information encrypted is at risk. For more information access: (https://security-code-scan.github.io/#SCS0010).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(DES.Create\(\))(([^A]|A[^e]|Ae[^s]|Aes[^M]|AesM[^a]|AesMa[^n]|AesMan[^a]|AesMana[^g]|AesManag[^e]|AesManage[^d])*)(Write\(.*\))`),
		},
	}
}

func NewCsharpRegularNoUseHtmlRaw() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e9527806-0f8e-4e9b-903c-549e1840b24a",
			Name:        "No use Html.Raw",
			Description: "The application uses the potentially dangerous Html.Raw construct in conjunction with a user-supplied variable. The recommendation is to avoid using HTML assembly, but if it is extremely necessary to allow Html, we suggest the following: support only a fixed subset of Html, after the user submits content, analyze the Html and filter it in a whitelist of allowed tags and attributes. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Html\.Raw\(`),
		},
	}
}

func NewCsharpRegularNoLogSensitiveInformation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "2da09ea2-b2bb-4ee6-8ec7-f3b390fdec7f",
			Name:        "No log sensitive information debug mode",
			Description: "The application is configured to display standard .NET errors. This can provide the attacker with useful information and should not be used in a production application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs. For more information checkout the CWE-12 (https://cwe.mitre.org/data/definitions/12.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`<\s*customErrors\s+mode\s*=\s*\"Off\"\s*/?>`),
		},
	}
}

func NewCsharpRegularNoReturnStringConcatInController() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b9b63a1c-33b3-43e5-82ce-aed6a58fb2fd",
			Name:        "No return string concat in controller",
			Description: "A potential Cross-Site Scripting (XSS) was found. The endpoint returns a variable from the client entry that has not been coded. Always encode untrusted input before output, regardless of validation or cleaning performed. https://docs.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-3.1. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?:public\sclass\s.*Controller|.*\s+:\s+Controller)(?:\n*.*)*return\s+.*\".*\+`),
		},
	}
}

func NewCsharpRegularSQLInjectionOdbcCommand() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "192e60ba-5454-4399-bbe3-8c4e75845a16",
			Name:        "SQL Injection OdbcCommand",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.*\s*new\sOdbcCommand\(.*\".*\+(?:.*\n*)*.ExecuteReader\(`),
		},
	}
}

func NewCsharpRegularWeakHashingFunctionMd5OrSha1() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "263e1cb3-31ee-443e-80e0-31f81bbfb340",
			Name:        "Weak hashing function md5 or sha1",
			Description: "MD5 or SHA1 have known collision weaknesses and are no longer considered strong hashing algorithms. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSHA1CryptoServiceProvider\(`),
			regexp.MustCompile(`new\sMD5CryptoServiceProvider\(`),
		},
	}
}

func NewCsharpRegularWeakHashingFunctionDESCrypto() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6ba6bebf-3626-4645-b2c7-f8e169e8db3d",
			Name:        "Weak hashing function DES Crypto",
			Description: "DES Crypto have known collision weaknesses and are no longer considered strong hashing algorithms. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sTripleDESCryptoServiceProvider\(`),
			regexp.MustCompile(`new\sDESCryptoServiceProvider\(`),
			regexp.MustCompile(`TripleDES\.Create\(`),
			regexp.MustCompile(`DES\.Create\(`),
		},
	}
}

func NewCsharpRegularNoUseCipherMode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1faf6a8f-94fe-4eed-a60c-4a4317b4bd25",
			Name:        "No Use Cipher mode",
			Description: "This mode is not recommended because it opens the door to various security exploits. If the plain text to be encrypted contains substantial repetitions, it is possible that the cipher text will be broken one block at a time. You can also use block analysis to determine the encryption key. In addition, an active opponent can replace and exchange individual blocks without detection, which allows the blocks to be saved and inserted into the stream at other points without detection. ECB and OFB mode will produce the same result for identical blocks. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CipherMode\.ECB`),
			regexp.MustCompile(`CipherMode\.OFB`),
			regexp.MustCompile(`CipherMode\.CTS`),
			regexp.MustCompile(`CipherMode\.CFB`),
		},
	}
}

func NewCsharpRegularDebugBuildEnabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e4c52f0d-abdb-4958-9e85-e7d34caf7e99",
			Name:        "Debug Build Enabled",
			Description: "Binaries compiled in debug mode can leak detailed stack traces and debugging messages to attackers. Disable debug builds by setting the debug attribute to false. For more information checkout the CWE-11 (https://cwe.mitre.org/data/definitions/11.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<compilation(\s|.)*debug\s*=\s*['|"]true['|"]`),
		},
	}
}

func NewCsharpRegularVulnerablePackageReference() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6d516e9e-8528-4a0a-801a-cd5f2fef1e0c",
			Name:        "Vulnerable Package Reference",
			Description: "Dependencies on open source frameworks and packages introduce additional vulnerabilities into the runtime environment. Vulnerabilities in open source libraries are continuously discovered and documented in publicly available vulnerability databases. Attackers can recognize a package being used by an application, and leverage known vulnerabilities in the library to attack the application. For more information checkout the CWE-937 (https://cwe.mitre.org/data/definitions/937.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`<package id="bootstrap" version="3\.0\.0" targetFramework="net462"/>`),
		},
	}
}

func NewCsharpRegularCorsAllowOriginWildCard() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6fa83684-e29d-44a8-ac20-bdd955d45363",
			Name:        "Cors Allow Origin Wild Card",
			Description: "Cross-Origin Resource Sharing (CORS) allows a service to disable the browser’s Same-origin policy, which prevents scripts on an attacker-controlled domain from accessing resources and data hosted on a different domain. The CORS Access-Control-Allow-Origin HTTP header specifies the domain with permission to invoke a cross-origin service and view the response data. Configuring the Access-Control-Allow-Origin header with a wildcard (*) can allow code running on an attacker-controlled domain to view responses containing sensitive data. For more information checkout the CWE-942 (https://cwe.mitre.org/data/definitions/942.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`app\.UseCors\(builder => builder\.AllowAnyOrigin\(\)\);`),
		},
	}
}

func NewCsharpRegularMissingAntiForgeryTokenAttribute() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "21debfa9-f639-4af2-bc33-b1399fc24a89",
			Name:        "Missing Anti Forgery Token Attribute",
			Description: "Cross Site Request Forgery attacks occur when a victim authenticates to a target web site and then visits a malicious web page. The malicious web page then sends a fake HTTP request (GET, POST, etc.) back to the target website. The victim’s valid authentication cookie from the target web site is automatically included in the malicious request, sent to the target web site, and processed as a valid transaction under the victim’s identity. For more information checkout the CWE-352 (https://cwe.mitre.org/data/definitions/352.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[HttpGet\]|\[HttpPost\]|\[HttpPut\]|\[HttpDelete\])(([^V]|V[^a]|Va[^l]|Val[^i]|Vali[^d]|Valid[^a]|Valida[^t]|Validat[^e]|Validate[^A]|ValidateA[^n]|ValidateAn[^t]|ValidateAnt[^i]|ValidateAnti[^F]|ValidateAntiF[^o]|ValidateAntiFo[^r]|ValidateAntiFor[^g]|ValidateAntiForg[^e]|ValidateAntiForge[^r]|ValidateAntiForger[^y]|ValidateAntiForgery[^T]|ValidateAntiForgeryT[^o]|ValidateAntiForgeryTo[^k]|ValidateAntiForgeryTok[^e]|ValidateAntiForgeryToke[^n])*)(ActionResult)`),
		},
	}
}

func NewCsharpRegularUnvalidatedWebFormsRedirect() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fa1a798e-b43f-43d1-8e13-2d53039e79ce",
			Name:        "Unvalidated Web Forms Redirect",
			Description: "Passing unvalidated redirect locations to the Response.Redirect method can allow attackers to send users to malicious web sites. This can allow attackers to perform phishing attacks and distribute malware to victims. For more information checkout the CWE-601 (https://cwe.mitre.org/data/definitions/601.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Response\.Redirect\(Request\.QueryString\[".*"\]\)`),
		},
	}
}

func NewCsharpRegularIdentityPasswordLockoutDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ab6aa12f-362c-4be2-8a5b-0e37b4b0d7a1",
			Name:        "Identity Password Lockout Disabled",
			Description: "Password lockout mechanisms help prevent continuous brute force attacks again user accounts by disabling an account for a period of time after a number of invalid attempts. The ASP.NET Identity SignInManager protects against brute force attacks if the lockout parameter is set to true. For more information checkout the CWE-307 (https://cwe.mitre.org/data/definitions/307.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CheckPasswordSignInAsync\(.*, .*, false\)`),
		},
	}
}

func NewCsharpRegularRawInlineExpression() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e6169641-f92d-492b-a6a8-cbe22e951abf",
			Name:        "Raw Inline Expression",
			Description: "Data is written to the browser using a raw write: <%= var %>. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Instead of using a raw write, use the inline HTML encoded shortcut (<%: var %>) to automatically HTML encode data before writing it to the browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<\%=.*\%\>`),
		},
	}
}

func NewCsharpRegularRawBindingExpression() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f148484d-23d3-41cf-9a51-f7bee058575d",
			Name:        "Raw Binding Expression",
			Description: "Data is written to the browser using a raw binding expression: <%# Item.Variable %>. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Instead of using a raw binding expression, use the HTML encoded binding shortcut (<%#: Item.Variable %>) to automatically HTML encode data before writing it to the browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<\%#[^:].*\%\>`),
		},
	}
}

func NewCsharpRegularRawWriteLiteralMethod() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "94179e8d-daf8-4632-9d8c-dcc687e440b6",
			Name:        "Raw Write Literal Method",
			Description: "Data is written to the browser using the raw WriteLiteral method. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Instead of using the raw WriteLiteral method, use a Razor helper that performs automatic HTML encoding before writing it to the browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`WriteLiteral\(`),
		},
	}
}

func NewCsharpRegularUnencodedWebFormsProperty() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b511f0cb-64da-40b8-ba18-dc7b78fed9d4",
			Name:        "Unencoded Web Forms Property",
			Description: "Data is written to the browser using a WebForms property that does not perform output encoding. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). WebForms controls are often found in HTML contexts, but can also appear in other contexts such as JavaScript, HTML Attribute, or URL. Fixing the vulnerability requires the appropriate Web Protection Library (aka AntiXSS) context-specific method to encode the data before setting the WebForms property. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(litDetails\.Text)(([^H]|H[^t]|Ht[^m]|Htm[^l]|Html[^E]|HtmlE[^n]|HtmlEn[^c]|HtmlEnc[^o]|HtmlEnco[^d]|HtmlEncod[^e])*)(;)`),
		},
	}
}

func NewCsharpRegularUnencodedLabelText() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4aa38f87-2ae0-4565-8b1b-c66128a5c206",
			Name:        "Unencoded Label Text",
			Description: "Data is written to the browser using the raw Label.Text method. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Label controls are often found in HTML contexts, but can also appear in other contexts such as JavaScript, HTML Attribute, or URL. Fixing the vulnerability requires the appropriate Web Protection Library (aka AntiXSS) context-specific method to encode the data before setting the Label.Text property. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(lblDetails\.Text)(([^H]|H[^t]|Ht[^m]|Htm[^l]|Html[^E]|HtmlE[^n]|HtmlEn[^c]|HtmlEnc[^o]|HtmlEnco[^d]|HtmlEncod[^e])*)(;)`),
		},
	}
}

func NewCsharpRegularWeakRandomNumberGenerator() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4b546b8d-0d0c-4b37-ad5f-f8f788019a3e",
			Name:        "Weak Random Number Generator",
			Description: "The use of a predictable random value can lead to vulnerabilities when used in certain security critical contexts. For more information access: (https://security-code-scan.github.io/#SCS0005) or (https://cwe.mitre.org/data/definitions/338.html).",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new Random\(\)`),
		},
	}
}

func NewCsharpRegularWeakRsaKeyLength() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "126b300d-d512-4ca4-a32a-3aad096edb35",
			Name:        "Weak Rsa Key Length",
			Description: "Due to advances in cryptanalysis attacks and cloud computing capabilities, the National Institute of Standards and Technology (NIST) deprecated 1024-bit RSA keys on January 1, 2011. The Certificate Authority Browser Forum, along with the latest version of all browsers, currently mandates a minimum key size of 2048-bits for all RSA keys. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new RSACryptoServiceProvider\()(\)|[0-9][^\d]|[0-9]{2}[^\d]|[0-9]{3}[^\d]|[0-1][0-9]{3}[^\d]|20[0-3][0-9]|204[0-7])`),
		},
	}
}

func NewCsharpRegularXmlReaderExternalEntityExpansion() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3a3f1a75-e2ab-4fc6-a366-517c5771ecae",
			Name:        "Xml Reader External Entity Expansion",
			Description: "XML External Entity (XXE) vulnerabilities occur when applications process untrusted XML data without disabling external entities and DTD processing. Processing untrusted XML data with a vulnerable parser can allow attackers to extract data from the server, perform denial of service attacks, and in some cases gain remote code execution. The XmlReaderSettings and XmlTextReader classes are vulnerable to XXE attacks when setting the DtdProcessing property to DtdProcessing.Parse or the ProhibitDtd property to false.\n\n \n\nTo prevent XmlReader XXE attacks, avoid using the deprecated ProhibitDtd property. Set the DtdProcessing property to DtdProcessing.Prohibit. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new\sXmlReaderSettings)(([^P]|P[^r]|Pr[^o]|Pro[^h]|Proh[^i]|Prohi[^b]|Prohib[^i]|Prohibi[^t])*)(})`),
		},
	}
}

func NewCsharpRegularLdapInjectionDirectoryEntry() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f5f1ace5-84f0-43ed-b9c1-60ced0286b73",
			Name:        "Ldap Injection Directory Entry",
			Description: "LDAP Injection vulnerabilities occur when untrusted data is concatenated into a LDAP Path or Filter expression without properly escaping control characters. This can allow attackers to change the meaning of an LDAP query and gain access to resources for which they are not authorized. Fixing the LDAP Injection Directory Entry vulnerability requires untrusted data to be encoded using the appropriate Web Protection Library (aka AntiXSS) LDAP encoding method: Encoder.LdapDistinguishedNameEncode(). For more information checkout the CWE-90 (https://cwe.mitre.org/data/definitions/90.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new\sDirectoryEntry\(.*LDAP.*\{)(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r])*)(;)`),
		},
	}
}
