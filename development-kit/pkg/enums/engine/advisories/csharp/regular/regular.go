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

func NewCsharpRegularPasswordComplexity() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7fefbb75-2c16-4651-ab8f-3bff4d4e1b78",
			Name:        "Password Complexity",
			Description: "PasswordValidator should have at least two requirements for better security, the RequiredLength property must be set with a minimum value of 8. For more information access: (https://security-code-scan.github.io/#SCS0027).",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new PasswordValidator\(\)`), // empty not allowed
			regexp.MustCompile(`new PasswordValidator\(\)`), // minimum of 2 properties
			regexp.MustCompile(`new PasswordValidator\(\)`), // RequiredLength greater than 8
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
			Description: "The validateRequest which provides additional protection against XSS is disabled in configuration file. For more information access: (https://security-code-scan.github.io/#SCS0017).",
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
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0035).",
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
			Description: "The viewStateEncryptionMode is not set to Always in configuration file. Web Forms controls use hidden base64 encoded fields to store state information. If sensitive information is stored there it may be leaked to the client side. For more information access: (https://security-code-scan.github.io/#SCS0023).",
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
			Description: "The enableViewStateMac is disabled in configuration file. (This feature cannot be disabled starting .NET 4.5.1). The view state could be altered by an attacker. For more information access: (https://security-code-scan.github.io/#SCS0024).",
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
			Name:        "No log sensitive information",
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
			Description: "This mode is not recommended because it opens the door to various security exploits. If the plain text to be encrypted contains substantial repetitions, it is possible that the cipher text will be broken one block at a time. You can also use block analysis to determine the encryption key. In addition, an active opponent can replace and exchange individual blocks without detection, which allows the blocks to be saved and inserted into the stream at other points without detection. ECB and OFB mode will produce the same result for identical blocks. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CipherMode\.ECB`),
			regexp.MustCompile(`CipherMode\.OFB`),
		},
	}
}

func NewCsharpRegularCrossSiteRequestForgery() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f7485b63-9cad-4159-8b05-0869b7d78195",
			Name:        "Cross-Site Request Forgery (CSRF)",
			Description: "Anti-forgery token is missing. An attacker could send a link to the victim. By visiting the malicious link, a web page would trigger a POST request (because it is a blind attack - the attacker doesn’t see a response from triggered request and has no use from GET request and GET requests should not change a state on the server by definition) to the website. The victim would not be able to acknowledge that an action is made in the background, but his cookie would be automatically submitted if he is authenticated to the website. For more information access: (https://security-code-scan.github.io/#SCS0016).",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?:public\s+class\s+.*Controller|.*\s+:\s+Controller)(([^V]|V[^a]|Va[^l]|Val[^i]|Vali[^d]|Valid[^a]|Valida[^t]|Validat[^e]|Validate[^A]|ValidateA[^n]|ValidateAn[^t]|ValidateAnt[^i]|ValidateAnti[^F]|ValidateAntiF[^o]|ValidateAntiFo[^r]|ValidateAntiFor[^g]|ValidateAntiForg[^e]|ValidateAntiForge[^r]|ValidateAntiForger[^y]|ValidateAntiForgery[^T]|ValidateAntiForgeryT[^o]|ValidateAntiForgeryTo[^k]|ValidateAntiForgeryTok[^e]|ValidateAntiForgeryToke[^n])*)(})`),
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
