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

//nolint:lll // multiple regex is not possible broken lines

package csharp

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewCommandInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-1",
			Name:        "Command Injection",
			Description: "If a malicious user controls either the FileName or Arguments, he might be able to execute unwanted commands or add unwanted argument. This behavior would not be possible if input parameter are validate against a white-list of characters. For more information access: (https://security-code-scan.github.io/#SCS0001).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new Process\(\)`),
			regexp.MustCompile(`StartInfo.FileName`),
			regexp.MustCompile(`StartInfo.Arguments`),
		},
	}
}

func NewXPathInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-2",
			Name:        "XPath Injection",
			Description: "If the user input is not properly filtered, a malicious user could extend the XPath query. For more information access: (https://security-code-scan.github.io/#SCS0003).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new XmlDocument {XmlResolver = null}`),
			regexp.MustCompile(`Load\(.*\)`),
			regexp.MustCompile(`SelectNodes\(.*\)`),
		},
	}
}

func NewExternalEntityInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-3",
			Name:        "XML eXternal Entity Injection (XXE)",
			Description: "The XML parser is configured incorrectly. The operation could be vulnerable to XML eXternal Entity (XXE) processing. For more information access: (https://security-code-scan.github.io/#SCS0007).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new XmlReaderSettings\(\)`),
			regexp.MustCompile(`XmlReader.Create\(.*\)`),
			regexp.MustCompile(`new XmlDocument\(.*\)`),
			regexp.MustCompile(`Load\(.*\)`),
			regexp.MustCompile(`ProhibitDtd = false`),
			regexp.MustCompile(`(new XmlReaderSettings\(\))(([^P]|P[^r]|Pr[^o]|Pro[^h]|Proh[^i]|Prohi[^b]|Prohib[^i]|Prohibi[^t]|Prohibit[^D]|ProhibitD[^t]|ProhibitDt[^d])*)(\.Load\(.*\))`),
		},
	}
}

func NewPathTraversal() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-4",
			Name:        "Path Traversal",
			Description: "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the expected directory.By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files. For more information access: (https://security-code-scan.github.io/#SCS0018).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ActionResult`),
			regexp.MustCompile(`System.IO.File.ReadAllBytes\(Server.MapPath\(.*\) \+ .*\)`),
			regexp.MustCompile(`File\(.*, System.Net.Mime.MediaTypeNames.Application.Octet, .*\)`),
		},
	}
}

func NewSQLInjectionWebControls() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-5",
			Name:        "SQL Injection WebControls",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0014).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`"Select .* From .* where .*" & .*`),
			regexp.MustCompile(`System\.Web\.UI\.WebControls\.SqlDataSource | System\.Web\.UI\.WebControls\.SqlDataSourceView | Microsoft\.Whos\.Framework\.Data\.SqlUtility`),
		},
	}
}

func NewWeakCipherOrCBCOrECBMode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-6",
			Name:        "Weak Cipher Mode",
			Description: "The cipher provides no way to detect that the data has been tampered with. If the cipher text can be controlled by an attacker, it could be altered without detection. The use of AES in CBC mode with a HMAC is recommended guaranteeing integrity and confidentiality. For more information access: (https://security-code-scan.github.io/#SCS0013).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(using)(([^O]|O[^r]|Or[^g]|Org[^.]|Org\.[^B]|Org\.B[^o]|Org\.Bo[^u]|Org\.Bou[^n]|Org\.Boun[^c]|Org\.Bounc[^y]|Org\.Bouncy[^C]|Org\.BouncyC[^a]|Org\.BouncyCa[^s]|Org\.BouncyCas[^t]|Org\.BouncyCast[^l]|Org\.BouncyCastl[^e])*)(\);)`),
			regexp.MustCompile(`CreateEncryptor\(.*\)`),
			regexp.MustCompile(`new CryptoStream\(.*\)`),
			regexp.MustCompile(`Write\(.*\)`),
			regexp.MustCompile(`new BinaryWriter\(.*\)`),
		},
	}
}

func NewFormsAuthenticationCookielessMode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-7",
			Name:        "Forms Authentication Cookieless Mode",
			Description: "Authentication cookies should not be sent in the URL. Doing so allows attackers to gain unauthorized access to authentication tokens (web server logs, referrer headers, and browser history) and more easily perform session fixation / hijacking attacks. For more information checkout the CWE-598 (https://cwe.mitre.org/data/definitions/598.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<authentication\s*mode\s*=\s*["|']Forms`),
			regexp.MustCompile(`(\<forms)((([^c]|c[^o]|co[^o]|coo[^k]|cook[^i]|cooki[^e]|cookie[^l]|cookiel[^e]|cookiele[^s]|cookieles[^s])*)|([^U]|U[^s]|Us[^e]|Use[^C]|UseC[^o]|UseCo[^o]|UseCoo[^k]|UseCook[^i]|UseCooki[^e]|UseCookie[^s])*)(\/\>)`),
		},
	}
}

func NewFormsAuthenticationCrossAppRedirects() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-8",
			Name:        "Forms Authentication Cross App Redirects",
			Description: "Enabling cross-application redirects can allow unvalidated redirect attacks via the returnUrl parameter during the login process. Disable cross-application redirects to by setting the enableCrossAppRedirects attribute to false. For more information checkout the CWE-601 (https://cwe.mitre.org/data/definitions/601.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<authentication\s*mode\s*=\s*["|']Forms`),
			regexp.MustCompile(`\<forms`),
			regexp.MustCompile(`enableCrossAppRedirects\s*=\s*["|']true`),
		},
	}
}

func NewFormsAuthenticationWeakCookieProtection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-9",
			Name:        "Forms Authentication Weak Cookie Protection",
			Description: "Forms Authentication cookies must use strong encryption and message authentication code (MAC) validation to protect the cookie value from inspection and tampering. Configure the forms element’s protection attribute to All to enable cookie data validation and encryption. For more information checkout the CWE-565 (https://cwe.mitre.org/data/definitions/565.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<authentication\s*mode\s*=\s*["|']Forms`),
			regexp.MustCompile(`\<forms`),
			regexp.MustCompile(`protection\s*=\s*["|'](None|Encryption|Validation)`),
		},
	}
}

func NewFormsAuthenticationWeakTimeout() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-10",
			Name:        "Forms Authentication Weak Timeout",
			Description: "Excessive authentication timeout values provide attackers with a large window of opportunity to hijack user’s authentication tokens. For more information checkout the CWE-613 (https://cwe.mitre.org/data/definitions/613.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<authentication\s*mode\s*=\s*["|']Forms`),
			regexp.MustCompile(`\<forms`),
			regexp.MustCompile(`timeout\s*=\s*["|'](1[6-9]|[2-9][0-9]*)`),
		},
	}
}

func NewHeaderCheckingDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-11",
			Name:        "Header Checking Disabled",
			Description: "Disabling the HTTP Runtime header checking protection opens the application up to HTTP Header Injection (aka Response Splitting) attacks. Enable the header checking protection by setting the httpRuntime element’s enableHeaderChecking attribute to true, which is the default value. For more information checkout the CWE-113 (https://cwe.mitre.org/data/definitions/113.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<httpRuntime`),
			regexp.MustCompile(`enableHeaderChecking\s*=\s*["|']false`),
		},
	}
}

func NewVersionHeaderEnabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-12",
			Name:        "Version Header Enabled",
			Description: "The Version HTTP response header sends the ASP.NET framework version to the client’s browser. This information can help an attacker identify vulnerabilities in the server’s framework version and should be disabled in production. Disable the version response header by setting the httpRuntime element’s enableVersionHeader attribute to false. For more information checkout the CWE-200 (https://cwe.mitre.org/data/definitions/200.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<httpRuntime`),
			regexp.MustCompile(`enableVersionHeader\s*=\s*["|']true`),
		},
	}
}

func NewEventValidationDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-13",
			Name:        "Event Validation Disabled",
			Description: "Event validation prevents unauthorized post backs in web form applications. Disabling this feature can allow attackers to forge requests from controls not visible or enabled on a given web form. Enable event validation by setting the page element’s eventValidation attribute to true. For more information checkout the CWE-807 (https://cwe.mitre.org/data/definitions/807.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<pages`),
			regexp.MustCompile(`enableEventValidation\s*=\s*["|']false`),
		},
	}
}

func NewWeakSessionTimeout() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-14",
			Name:        "Weak Session Timeout",
			Description: "If session data is used by the application for authentication, excessive timeout values provide attackers with a large window of opportunity to hijack user’s session tokens. Configure the session timeout value to meet your organization’s timeout policy. For more information checkout the CWE-613 (https://cwe.mitre.org/data/definitions/613.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<sessionState`),
			regexp.MustCompile(`timeout\s*=\s*["|'](1[6-9]|[2-9][0-9]*)`),
		},
	}
}

func NewStateServerMode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-15",
			Name:        "Weak Session Timeout",
			Description: "The session StateServer mode transports session data insecurely to a remote server. The remote server also does not require system authentication to access the session data for an application. This risk depends entirely on the sensitivity of the data stored in the user’s session. If the session data is considered sensitive, consider adding an external control (e.g. IPSEC) that provides mutual authentication and transport security. For more information checkout the CWE-319 (https://cwe.mitre.org/data/definitions/319.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<sessionState`),
			regexp.MustCompile(`mode\s*=\s*["|']StateServer`),
		},
	}
}

func NewJwtSignatureValidationDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-16",
			Name:        "Jwt Signature Validation Disabled",
			Description: "Web service APIs relying on JSON Web Tokens (JWT) for authentication and authorization must sign each JWT with a private key or secret. Each web service endpoint must require JWT signature validation prior to decoding and using the token to access protected resources. The values RequireExpirationTime, RequireSignedTokens, ValidateLifetime can't was false. For more information checkout the CWE-347 (https://cwe.mitre.org/data/definitions/347.html) and CWE-613 (https://cwe.mitre.org/data/definitions/613.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`AddAuthentication\(.*\)`),
			regexp.MustCompile(`AddJwtBearer`),
			regexp.MustCompile(`new TokenValidationParameters`),
			regexp.MustCompile(`(RequireExpirationTime\s*=\s*false|RequireSignedTokens\s*=\s*false|ValidateLifetime\s*=\s*false)`),
		},
	}
}

func NewInsecureHttpCookieTransport() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-17",
			Name:        "Insecure Http Cookie Transport",
			Description: "Cookies containing authentication tokens, session tokens, and other state management credentials must be protected in transit across a network. Set the cookie options’ Secure property to true to prevent the browser from transmitting cookies over HTTP. For more information checkout the CWE-614 (https://cwe.mitre.org/data/definitions/614.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sCookieOptions\(\)`),
			regexp.MustCompile(`Secure\s*=\s*false`),
		},
	}
}

func NewHttpCookieAccessibleViaScript() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-18",
			Name:        "Http Cookie Accessible Via Script",
			Description: "Cookies containing authentication tokens, session tokens, and other state management credentials should be protected from malicious JavaScript running in the browser. Setting the httpOnly attribute to false can allow attackers to inject malicious scripts into the site and extract authentication cookie values to a remote server. Configure the cookie options’ httpOnly property to true, which prevents cookie access from scripts running in the browser. For more information checkout the CWE-1004 (https://cwe.mitre.org/data/definitions/1004.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sCookieOptions\(\)`),
			regexp.MustCompile(`HttpOnly\s*=\s*false`),
		},
	}
}

func NewDirectoryListingEnabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-19",
			Name:        "Directory Listing Enabled",
			Description: "Directory listing provides a complete index of the resources located in a web directory. Enabling directory listing can expose sensitive resources such as application binaries, configuration files, and static content that should not be exposed. Unless directory listing is required to meet the application’s functional requirements, disable the listing by setting the directoryBrowse element’s enabled attribute to false. For more information checkout the CWE-548 (https://cwe.mitre.org/data/definitions/548.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<directoryBrowse`),
			regexp.MustCompile(`enabled\s*=\s*['|"]true`),
		},
	}
}

func NewLdapAuthenticationDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-20",
			Name:        "Ldap Authentication Disabled",
			Description: "Disabling LDAP Authentication configures insecure connections to the backend LDAP provider. Using the DirectoryEntry AuthenticationType property’s Anonymous or None option allows an anonymous or basic authentication connection to the LDAP provider. Set the the DirectoryEntry AuthenticationType property to Secure, which requests Kerberos authentication under the security context of the calling thread or as a provider username and password. For more information checkout the CWE-287 (https://cwe.mitre.org/data/definitions/287.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sDirectoryEntry\(.*\)`),
			regexp.MustCompile(`AuthenticationTypes.Anonymous`),
		},
	}
}

func NewCertificateValidationDisabledAndMatch() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-21",
			Name:        "Certificate Validation Disabled",
			Description: "Disabling certificate validation is common in testing and development environments. Quite often, this is accidentally deployed to production, leaving the application vulnerable to man-in-the-middle attacks on insecure networks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new WebRequestHandler\(\)`),
			regexp.MustCompile(`ServerCertificateValidationCallback \+= \(.*\) => true;`),
		},
	}
}

func NewActionRequestValidationDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-22",
			Name:        "Action Request Validation Disabled",
			Description: "Request validation performs blacklist input validation for XSS payloads found in form and URL request parameters. Request validation has known bypass issues and does not prevent all XSS attacks, but it does provide a strong countermeasure for most payloads targeting a HTML context. For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[HttpGet\(.*\)\]|\[HttpPost\(.*\)\]|\[HttpPut\(.*\)\]|\[HttpDelete\(.*\)\]|\[HttpGet\]|\[HttpPost\]|\[HttpPut\]|\[HttpDelete\])`),
			regexp.MustCompile(`\[ValidateInput\(false\)\]`),
		},
	}
}

func NewXmlDocumentExternalEntityExpansion() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-23",
			Name:        "Xml Document External Entity Expansion",
			Description: "XML External Entity (XXE) vulnerabilities occur when applications process untrusted XML data without disabling external entities and DTD processing. Processing untrusted XML data with a vulnerable parser can allow attackers to extract data from the server, perform denial of service attacks, and in some cases gain remote code execution. The XmlDocument class is vulnerable to XXE attacks when setting the XmlResolver property to resolve external entities. To prevent XmlDocument XXE attacks, set the XmlResolver property to null. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sXmlDocument`),
			regexp.MustCompile(`(XmlResolver)(([^n]|n[^u]|nu[^l]|nul[^l])*)(;)`),
		},
	}
}

func NewLdapInjectionFilterAssignment() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-24",
			Name:        "Ldap Injection Filter Assignment",
			Description: "LDAP Injection vulnerabilities occur when untrusted data is concatenated into a LDAP Path or Filter expression without properly escaping control characters. This can allow attackers to change the meaning of an LDAP query and gain access to resources for which they are not authorized. For more information checkout the CWE-90 (https://cwe.mitre.org/data/definitions/90.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new DirectoryEntry\(.*\)`),
			regexp.MustCompile(`new DirectorySearcher\(.*\)`),
			regexp.MustCompile(`(\.Filter)(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r]|Encoder[^.]|Encoder\.[^L]|Encoder\.L[^d]|Encoder\.Ld[^a]|Encoder\.Lda[^p]|Encoder\.Ldap[^F]|Encoder\.LdapF[^i]|Encoder\.LdapFi[^l]|Encoder\.LdapFil[^t]|Encoder\.LdapFilt[^e]|Encoder\.LdapFilte[^r]|Encoder\.LdapFilter[^E]|Encoder\.LdapFilterE[^n]|Encoder\.LdapFilterEn[^c]|Encoder\.LdapFilterEnc[^o]|Encoder\.LdapFilterEnco[^d]|Encoder\.LdapFilterEncod[^e])*)(\);)`),
		},
	}
}

func NewSqlInjectionDynamicNHibernateQuery() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-25",
			Name:        "Sql Injection: Dynamic NHibernate Query",
			Description: "Concatenating untrusted data into a dynamic SQL string and calling vulnerable NHibernate Framework methods can allow SQL Injection. To ensure calls to vulnerable NHibernate Framework methods are parameterized, pass positional or named parameters in the statement. The following NHibernate methods allow for raw SQL queries to be executed: CreateQuery CreateSqlQuery To ensure calls to vulnerable NHibernate methods are parameterized, use named parameters in the raw SQL query. Then, set the named parameter values when executing the query. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)["|'](SELECT|INSERT|UPDATE|DELETE).*\+`),
			regexp.MustCompile(`(CreateQuery\(.*\);)(([^S]|S[^e]|Se[^t]|Set[^S]|SetS[^t]|SetSt[^r]|SetStr[^i]|SetStri[^n]|SetStrin[^g])*)(;)`),
		},
	}
}

func NewLdapInjectionDirectorySearcher() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-26",
			Name:        "Ldap Injection Directory Searcher",
			Description: "LDAP Injection vulnerabilities occur when untrusted data is concatenated into a LDAP Path or Filter expression without properly escaping control characters. This can allow attackers to change the meaning of an LDAP query and gain access to resources for which they are not authorized. For more information checkout the CWE-90 (https://cwe.mitre.org/data/definitions/90.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new DirectoryEntry\(.*\)`),
			regexp.MustCompile(`(new DirectorySearcher)(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r]|Encoder[^.]|Encoder\.[^L]|Encoder\.L[^d]|Encoder\.Ld[^a]|Encoder\.Lda[^p]|Encoder\.Ldap[^F]|Encoder\.LdapF[^i]|Encoder\.LdapFi[^l]|Encoder\.LdapFil[^t]|Encoder\.LdapFilt[^e]|Encoder\.LdapFilte[^r]|Encoder\.LdapFilter[^E]|Encoder\.LdapFilterE[^n]|Encoder\.LdapFilterEn[^c]|Encoder\.LdapFilterEnc[^o]|Encoder\.LdapFilterEnco[^d]|Encoder\.LdapFilterEncod[^e])*)(\);)`),
		},
	}
}

func NewLdapInjectionPathAssignment() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-27",
			Name:        "Ldap Injection Path Assignment",
			Description: "LDAP Injection vulnerabilities occur when untrusted data is concatenated into a LDAP Path or Filter expression without properly escaping control characters. This can allow attackers to change the meaning of an LDAP query and gain access to resources for which they are not authorized. For more information checkout the CWE-90 (https://cwe.mitre.org/data/definitions/90.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new DirectoryEntry\(\)`),
			regexp.MustCompile(`(\.Path)(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r]|Encoder[^.]|Encoder\.[^L]|Encoder\.L[^d]|Encoder\.Ld[^a]|Encoder\.Lda[^p]|Encoder\.Ldap[^D]|Encoder\.LdapD[^i]|Encoder\.LdapDi[^s]|Encoder\.LdapDis[^t]|Encoder\.LdapDist[^i]|Encoder\.LdapDisti[^n]|Encoder\.LdapDistin[^g]|Encoder\.LdapDisting[^u]|Encoder\.LdapDistingu[^i]|Encoder\.LdapDistingui[^s]|Encoder\.LdapDistinguis[^h]|Encoder\.LdapDistinguish[^e]|Encoder\.LdapDistinguishe[^d]|Encoder\.LdapDistinguished[^N]|Encoder\.LdapDistinguishedN[^a]|Encoder\.LdapDistinguishedNa[^m]|Encoder\.LdapDistinguishedNam[^e]|Encoder\.LdapDistinguishedName[^E]|Encoder\.LdapDistinguishedNameE[^n]|Encoder\.LdapDistinguishedNameEn[^c]|Encoder\.LdapDistinguishedNameEnc[^o]|Encoder\.LdapDistinguishedNameEnco[^d]|Encoder\.LdapDistinguishedNameEncod[^e])*)(\);)`),
		},
	}
}

func NewLDAPInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-28",
			Name:        "LDAP Injection",
			Description: "The dynamic value passed to the LDAP query should be validated. For more information access: (https://security-code-scan.github.io/#SCS0031).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new DirectorySearcher\(\))(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r]|Encoder[^.]|Encoder\.[^L]|Encoder\.L[^d]|Encoder\.Ld[^a]|Encoder\.Lda[^p]|Encoder\.Ldap[^F]|Encoder\.LdapF[^i]|Encoder\.LdapFi[^l]|Encoder\.LdapFil[^t]|Encoder\.LdapFilt[^e]|Encoder\.LdapFilte[^r]|Encoder\.LdapFilter[^E]|Encoder\.LdapFilterE[^n]|Encoder\.LdapFilterEn[^c]|Encoder\.LdapFilterEnc[^o]|Encoder\.LdapFilterEnco[^d]|Encoder\.LdapFilterEncod[^e])*)(\)";)`),
			regexp.MustCompile(`(new DirectoryEntry\(\))(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r]|Encoder[^.]|Encoder\.[^L]|Encoder\.L[^d]|Encoder\.Ld[^a]|Encoder\.Lda[^p]|Encoder\.Ldap[^D]|Encoder\.LdapD[^i]|Encoder\.LdapDi[^s]|Encoder\.LdapDis[^t]|Encoder\.LdapDist[^i]|Encoder\.LdapDisti[^n]|Encoder\.LdapDistin[^g]|Encoder\.LdapDisting[^u]|Encoder\.LdapDistingu[^i]|Encoder\.LdapDistingui[^s]|Encoder\.LdapDistinguis[^h]|Encoder\.LdapDistinguish[^e]|Encoder\.LdapDistinguishe[^d]|Encoder\.LdapDistinguished[^N]|Encoder\.LdapDistinguishedN[^a]|Encoder\.LdapDistinguishedNa[^m]|Encoder\.LdapDistinguishedNam[^e]|Encoder\.LdapDistinguishedName[^E]|Encoder\.LdapDistinguishedNameE[^n]|Encoder\.LdapDistinguishedNameEn[^c]|Encoder\.LdapDistinguishedNameEnc[^o]|Encoder\.LdapDistinguishedNameEnco[^d]|Encoder\.LdapDistinguishedNameEncod[^e])*)(,.*";)`),
		},
	}
}

func NewSQLInjectionLinq() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-29",
			Name:        "SQL Injection LINQ",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database.. For more information access: (https://security-code-scan.github.io/#SCS0002).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(var|ExecuteQuery).*(=|\().*(SELECT|UPDATE|DELETE|INSERT).*\++`),
		},
	}
}

func NewInsecureDeserialization() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-30",
			Name:        "Insecure Deserialization",
			Description: "Arbitrary code execution, full application compromise or denial of service. An attacker may pass specially crafted serialized .NET object of specific class that will execute malicious code during the construction of the object. For more information access: (https://security-code-scan.github.io/#SCS0028).",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sBinaryFormatter\(\)\.Deserialize\(.*\)`),
			regexp.MustCompile(`new\sJavaScriptSerializer\(..*\)`),
		},
	}
}

func NewSQLInjectionEnterpriseLibraryData() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-31",
			Name:        "SQL Injection Enterprise Library Data",
			Description: "Arbitrary code execution, full application compromise or denial of service. An attacker may pass specially crafted serialized .NET object of specific class that will execute malicious code during the construction of the object. For more information access: (https://security-code-scan.github.io/#SCS0036).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(GetSqlStringCommand\(.*\))(([^A]|A[^d]|Ad[^d]|Add[^I]|AddI[^n]|AddIn[^P]|AddInP[^a]|AddInPa[^r]|AddInPar[^a]|AddInPara[^m]|AddInParam[^e]|AddInParame[^t]|AddInParamet[^e]|AddInParamete[^r])*)(ExecuteDataSet\(.*\))`),
			regexp.MustCompile(`ExecuteDataSet\(CommandType.*, "(SELECT|select).*(FROM|from).*(WHERE|where).*"\)`),
		},
	}
}

func NewCQLInjectionCassandra() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-32",
			Name:        "CQL Injection Cassandra",
			Description: "Arbitrary code execution, full application compromise or denial of service. An attacker may pass specially crafted serialized .NET object of specific class that will execute malicious code during the construction of the object. For more information access: (https://security-code-scan.github.io/#SCS0038).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(Prepare\("(SELECT|select).*(FROM|from).*(WHERE|where).*\))(([^B]|B[^i]|Bi[^n]|Bin[^d])*)(Execute\(.*\))`),
			regexp.MustCompile(`Execute\("(SELECT|select).*(FROM|from).*(WHERE|where).*"\)`),
		},
	}
}

func NewPasswordComplexity() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-33",
			Name:        "Password Complexity",
			Description: "PasswordValidator should have at least two requirements for better security, the RequiredLength property must be set with a minimum value of 8. For more information access: (https://security-code-scan.github.io/#SCS0027).",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sPasswordValidator\(\)`),
			regexp.MustCompile(`new\sPasswordValidator(\n?\s*{)(\n*.*=.*,?)(\s|\n)*[^a-z]}`),
			regexp.MustCompile(`new\sPasswordValidator(\n?\s*{)((\n|.*)*RequiredLength=[0-7][^\d])`),
			regexp.MustCompile(`(new\sPasswordValidator)(([^R]|R[^e]|Re[^q]|Req[^u]|Requ[^i]|Requi[^r]|Requir[^e]|Require[^d]|Required[^L]|RequiredL[^e]|RequiredLe[^n]|RequiredLen[^g]|RequiredLeng[^t]|RequiredLengt[^h])*)(})`),
		},
	}
}

func NewCookieWithoutSSLFlag() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-34",
			Name:        "Cookie Without SSL Flag",
			Description: "It is recommended to specify the Secure flag to new cookie. The Secure flag is a directive to the browser to make sure that the cookie is not sent by unencrypted channel. For more information access: (https://security-code-scan.github.io/#SCS0008) and (https://cwe.mitre.org/data/definitions/614.html).",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`requireSSL\s*=\s*['|"]false['|"]`),
			regexp.MustCompile(`(\<forms)(([^r]|r[^e]|re[^q]|req[^u]|requ[^i]|requi[^r]|requir[^e]|require[^S]|requireS[^S]|requireSS[^L])*)(\/\>)`),
			regexp.MustCompile(`(new\sHttpCookie\(.*\))(.*|\n)*(\.Secure\s*=\s*false)`),
			regexp.MustCompile(`(new\sHttpCookie)(([^S]|S[^e]|Se[^c]|Sec[^u]|Secu[^r]|Secur[^e])*)(})`),
		},
	}
}

func NewCookieWithoutHttpOnlyFlag() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-35",
			Name:        "Cookie Without HttpOnly Flag",
			Description: "It is recommended to specify the HttpOnly flag to new cookie. For more information access: (https://security-code-scan.github.io/#SCS0009) or (https://cwe.mitre.org/data/definitions/1004.html).",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`httpOnlyCookies\s*=\s*['|"]false['|"]`),
			regexp.MustCompile(`(new\sHttpCookie\(.*\))(.*|\n)*(\.HttpOnly\s*=\s*false)`),
			regexp.MustCompile(`(new\sHttpCookie)(([^H]|H[^t]|Ht[^t]|Htt[^p]|Http[^O]|HttpO[^n]|HttpOn[^l]|HttpOnl[^y])*)(})`),
		},
	}
}

func NewNoInputVariable() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-36",
			Name:        "No input variable",
			Description: "The application appears to allow XSS through an unencrypted / unauthorized input variable. https://owasp.org/www-community/attacks/xss/. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\s*var\s+\w+\s*=\s*"\s*\<\%\s*=\s*\w+\%\>";`),
			regexp.MustCompile(`\.innerHTML\s*=\s*.+`),
		},
	}
}

func NewIdentityWeakPasswordComplexity() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-37",
			Name:        "Identity Weak Password Complexity",
			Description: "Weak passwords can allow attackers to easily guess user passwords using wordlist or brute force attacks. Enforcing a strict password complexity policy mitigates these attacks by significantly increasing the time to guess a user’s valid password. For more information checkout the CWE-521 (https://cwe.mitre.org/data/definitions/521.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new PasswordValidator\(\)`),
			regexp.MustCompile(`RequiredLength = \b([0-7])\b`),
			regexp.MustCompile(`(new PasswordValidator)(([^R]|R[^e]|Re[^q]|Req[^u]|Requ[^i]|Requi[^r]|Requir[^e]|Require[^d]|Required[^L]|RequiredL[^e]|RequiredLe[^n]|RequiredLen[^g]|RequiredLeng[^t]|RequiredLengt[^h])*)(};)`),
			regexp.MustCompile(`(new PasswordValidator)(([^R]|R[^e]|Re[^q]|Req[^u]|Requ[^i]|Requi[^r]|Requir[^e]|Require[^D]|RequireD[^i]|RequireDi[^g]|RequireDig[^i]|RequireDigi[^t]|RequireDigit[^ ]|RequireDigit [^=]|RequireDigit =[^ ]|RequireDigit = [^t]|RequireDigit = t[^r]|RequireDigit = tr[^u]|RequireDigit = tru[^e])*)(};)`),
			regexp.MustCompile(`(new PasswordValidator)(([^R]|R[^e]|Re[^q]|Req[^u]|Requ[^i]|Requi[^r]|Requir[^e]|Require[^L]|RequireL[^o]|RequireLo[^w]|RequireLow[^e]|RequireLowe[^r]|RequireLower[^c]|RequireLowerc[^a]|RequireLowerca[^s]|RequireLowercas[^e]|RequireLowercase[^ ]|RequireLowercase [^=]|RequireLowercase =[^ ]|RequireLowercase = [^t]|RequireLowercase = t[^r]|RequireLowercase = tr[^u]|RequireLowercase = tru[^e])*)(};)`),
			regexp.MustCompile(`(new PasswordValidator)(([^R]|R[^e]|Re[^q]|Req[^u]|Requ[^i]|Requi[^r]|Requir[^e]|Require[^N]|RequireN[^o]|RequireNo[^n]|RequireNon[^L]|RequireNonL[^e]|RequireNonLe[^t]|RequireNonLet[^t]|RequireNonLett[^e]|RequireNonLette[^r]|RequireNonLetter[^O]|RequireNonLetterO[^r]|RequireNonLetterOr[^D]|RequireNonLetterOrD[^i]|RequireNonLetterOrDi[^g]|RequireNonLetterOrDig[^i]|RequireNonLetterOrDigi[^t]|RequireNonLetterOrDigit[^ ]|RequireNonLetterOrDigit [^=]|RequireNonLetterOrDigit =[^ ]|RequireNonLetterOrDigit = [^t]|RequireNonLetterOrDigit = t[^r]|RequireNonLetterOrDigit = tr[^u]|RequireNonLetterOrDigit = tru[^e])*)(};)`),
			regexp.MustCompile(`(new PasswordValidator)(([^R]|R[^e]|Re[^q]|Req[^u]|Requ[^i]|Requi[^r]|Requir[^e]|Require[^U]|RequireU[^p]|RequireUp[^p]|RequireUpp[^e]|RequireUppe[^r]|RequireUpper[^c]|RequireUpper[^c]|RequireUpperc[^a]|RequireUpperca[^s]|RequireUppercas[^e]|RequireUppercase[^ ]|RequireUppercase [^=]|RequireUppercase =[^ ]|RequireUppercase = [^t]|RequireUppercase = t[^r]|RequireUppercase = tr[^u]|RequireUppercase = tru[^e])*)(};)`),
		},
	}
}

func NewNoLogSensitiveInformationInConsole() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-38",
			Name:        "No Log Sensitive Information in console",
			Description: "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(((Log|log).*\.(Verbose|Debug|Info|Warn|Erro|ForContext|FromLogContext|Seq))|(Console.Write))`),
		},
	}
}

func NewOutputCacheConflict() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-39",
			Name:        "OutputCache Conflict",
			Description: "Having the annotation [OutputCache] will disable the annotation [Authorize] for the requests following the first one. For more information access: (https://security-code-scan.github.io/#SCS0019).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[Authorize\])(.*|\n)*(\[OutputCache\])`),
		},
	}
}

func NewOpenRedirect() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-40",
			Name:        "Open Redirect",
			Description: "Your site may be used in phishing attacks. An attacker may craft a trustworthy looking link to your site redirecting a victim to a similar looking malicious site: 'http://yourdomain.com?redirect=https://urdomain.com/login'. For more information access: (https://security-code-scan.github.io/#SCS0027).",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`String.IsNullOrEmpty.*\n?.*{?\n?.*return\sRedirect\(.*\);`),
		},
	}
}

func NewRequestValidationDisabledAttribute() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-41",
			Name:        "Request Validation Disabled (Attribute)",
			Description: "Request validation is disabled. Request validation allows the filtering of some XSS patterns submitted to the application. For more information access: (https://security-code-scan.github.io/#SCS0017).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\[ValidateInput\(false\)\]`),
		},
	}
}

func NewSQLInjectionOLEDB() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-42",
			Name:        "SQL Injection OLE DB",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0020).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new OleDbConnection\(.*\))(([^P]|P[^a]|Pa[^r]|Par[^a]|Para[^m]|Param[^e]|Parame[^t]|Paramet[^e]|Paramete[^r]|Parameter[^s]|Parameters[^.]|Parameters\.[^A]|Parameters\.A[^d]|Parameters\.Ad[^d])*)(\.ExecuteReader\(.*\))`),
		},
	}
}

func NewRequestValidationDisabledConfigurationFile() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-43",
			Name:        "Request Validation Disabled (Configuration File)",
			Description: "The validateRequest which provides additional protection against XSS is disabled in configuration file. For more information access: (https://security-code-scan.github.io/#SCS0017) or (https://cwe.mitre.org/data/definitions/20.html).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`validateRequest\s*=\s*['|"]false['|"]`),
		},
	}
}

func NewSQLInjectionMsSQLDataProvider() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-44",
			Name:        "SQL Injection MsSQL Data Provider",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0026).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new SqlCommand\(.*\))(([^P]|P[^a]|Pa[^r]|Par[^a]|Para[^m]|Param[^e]|Parame[^t]|Paramet[^e]|Paramete[^r]|Parameter[^s]|Parameters[^.]|Parameters\.[^A]|Parameters\.A[^d]|Parameters\.Ad[^d]|Parameters\.Add[^W]|Parameters\.AddW[^i]|Parameters\.AddWi[^t]|Parameters\.AddWit[^h]|Parameters\.AddWith[^V]|Parameters\.AddWithV[^a]|Parameters\.AddWithVa[^l]|Parameters\.AddWithVal[^u]|Parameters\.AddWithValu[^e])*)(Open\(\)|ExecuteReader\(\))`),
		},
	}
}

func NewRequestValidationIsEnabledOnlyForPages() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-45",
			Name:        "Request validation is enabled only for pages",
			Description: "The requestValidationMode which provides additional protection against XSS is enabled only for pages, not for all HTTP requests in configuration file. For more information access: (https://security-code-scan.github.io/#SCS0030).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`requestValidationMode\s*=\s*['|"][0-3][^\d].*['|"]`),
		},
	}
}

func NewSQLInjectionEntityFramework() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-46",
			Name:        "SQL Injection Entity Framework",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database, please use SqlParameter to create query with parameters. For more information access: (https://security-code-scan.github.io/#SCS0035) or (https://cwe.mitre.org/data/definitions/89.html) .",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(Database\.ExecuteSqlCommand)(([^S]|S[^q]|Sq[^l]|Sql[^P]|SqlP[^a]|SqlPa[^r]|SqlPar[^a]|SqlPara[^m]|SqlParam[^e]|SqlParame[^t]|SqlParamet[^e]|SqlParamete[^r])*)(\);)`),
		},
	}
}

func NewViewStateNotEncrypted() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-47",
			Name:        "View State Not Encrypted",
			Description: "The viewStateEncryptionMode is not set to Always in configuration file. Web Forms controls use hidden base64 encoded fields to store state information. If sensitive information is stored there it may be leaked to the client side. For more information access: (https://security-code-scan.github.io/#SCS0023) or (https://cwe.mitre.org/data/definitions/200.html).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`viewStateEncryptionMode\s*=\s*['|"](Auto|Never)['|"]`),
		},
	}
}

func NewSQLInjectionNhibernate() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-48",
			Name:        "SQL Injection Nhibernate",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0037).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(CreateSQLQuery)(([^S]|S[^e]|Se[^t]|Set[^P]|SetP[^a]|SetPa[^r]|SetPar[^a]|SetPara[^m]|SetParam[^e]|SetParame[^t]|SetParamet[^e]|SetParamete[^r])*)(\);)`),
		},
	}
}

func NewViewStateMacDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-49",
			Name:        "View State MAC Disabled",
			Description: "The enableViewStateMac is disabled in configuration file. (This feature cannot be disabled starting .NET 4.5.1). The view state could be altered by an attacker. For more information access: (https://security-code-scan.github.io/#SCS0024) or (https://cwe.mitre.org/data/definitions/807.html).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`enableViewStateMac\s*=\s*['|"]false['|"]`),
		},
	}
}

func NewSQLInjectionNpgsql() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-50",
			Name:        "SQL Injection Npgsql",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0039).",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(NpgsqlCommand\(.*\))(([^P]|P[^a]|Pa[^r]|Par[^a]|Para[^m]|Param[^e]|Parame[^t]|Paramet[^e]|Paramete[^r]|Parameter[^s]|Parameters[^.]|Parameters\.[^A]|Parameters\.A[^d]|Parameters\.Ad[^d]|Parameters\.Add[^W]|Parameters\.AddW[^i]|Parameters\.AddWi[^t]|Parameters\.AddWit[^h]|Parameters\.AddWith[^V]|Parameters\.AddWithV[^a]|Parameters\.AddWithVa[^l]|Parameters\.AddWithVal[^u]|Parameters\.AddWithValu[^e])*)(ExecuteNonQuery\(.*\)|ExecuteReader\(.*\))`),
		},
	}
}

func NewCertificateValidationDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-51",
			Name:        "Certificate Validation Disabled",
			Description: "Disabling certificate validation is often used to connect easily to a host that is not signed by a root certificate authority. As a consequence, this is vulnerable to Man-in-the-middle attacks since the client will trust any certificate. For more information access: (https://security-code-scan.github.io/#SCS0004).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ServicePointManager\.ServerCertificateValidationCallback \+= (.*) => true;`),
		},
	}
}

func NewWeakCipherAlgorithm() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-52",
			Name:        "Weak cipher algorithm",
			Description: "Broken or deprecated ciphers have typically known weakness. A attacker might be able to brute force the secret key use for the encryption. The confidentiality and integrity of the information encrypted is at risk. For more information access: (https://security-code-scan.github.io/#SCS0010).",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(DES.Create\(\))(([^A]|A[^e]|Ae[^s]|Aes[^M]|AesM[^a]|AesMa[^n]|AesMan[^a]|AesMana[^g]|AesManag[^e]|AesManage[^d])*)(Write\(.*\))`),
		},
	}
}

func NewNoUseHtmlRaw() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-53",
			Name:        "No use Html.Raw",
			Description: "The application uses the potentially dangerous Html.Raw construct in conjunction with a user-supplied variable. The recommendation is to avoid using HTML assembly, but if it is extremely necessary to allow Html, we suggest the following: support only a fixed subset of Html, after the user submits content, analyze the Html and filter it in a whitelist of allowed tags and attributes. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Html\.Raw\(`),
		},
	}
}

func NewNoLogSensitiveInformation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-54",
			Name:        "No log sensitive information debug mode",
			Description: "The application is configured to display standard .NET errors. This can provide the attacker with useful information and should not be used in a production application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs. For more information checkout the CWE-12 (https://cwe.mitre.org/data/definitions/12.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`<\s*customErrors\s+mode\s*=\s*\"Off\"\s*/?>`),
		},
	}
}

func NewNoReturnStringConcatInController() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-55",
			Name:        "No return string concat in controller",
			Description: "A potential Cross-Site Scripting (XSS) was found. The endpoint returns a variable from the client entry that has not been coded. Always encode untrusted input before output, regardless of validation or cleaning performed. https://docs.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-3.1. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?:public\sclass\s.*Controller|.*\s+:\s+Controller)(?:\n*.*)*return\s+.*\".*\+`),
		},
	}
}

func NewSQLInjectionOdbcCommand() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-56",
			Name:        "SQL Injection OdbcCommand",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`.*\s*new\sOdbcCommand\(.*\".*\+(?:.*\n*)*.ExecuteReader\(`),
		},
	}
}

func NewWeakHashingFunctionMd5OrSha1() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-57",
			Name:        "Weak hashing function md5 or sha1",
			Description: "MD5 or SHA1 have known collision weaknesses and are no longer considered strong hashing algorithms. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sSHA1CryptoServiceProvider\(`),
			regexp.MustCompile(`new\sMD5CryptoServiceProvider\(`),
		},
	}
}

func NewWeakHashingFunctionDESCrypto() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-58",
			Name:        "Weak hashing function DES Crypto",
			Description: "DES Crypto have known collision weaknesses and are no longer considered strong hashing algorithms. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severities.Medium.ToString(),
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

func NewNoUseCipherMode() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-59",
			Name:        "No Use Cipher mode",
			Description: "This mode is not recommended because it opens the door to various security exploits. If the plain text to be encrypted contains substantial repetitions, it is possible that the cipher text will be broken one block at a time. You can also use block analysis to determine the encryption key. In addition, an active opponent can replace and exchange individual blocks without detection, which allows the blocks to be saved and inserted into the stream at other points without detection. ECB and OFB mode will produce the same result for identical blocks. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
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

func NewDebugBuildEnabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-60",
			Name:        "Debug Build Enabled",
			Description: "Binaries compiled in debug mode can leak detailed stack traces and debugging messages to attackers. Disable debug builds by setting the debug attribute to false. For more information checkout the CWE-11 (https://cwe.mitre.org/data/definitions/11.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<compilation(\s|.)*debug\s*=\s*['|"]true['|"]`),
		},
	}
}

func NewVulnerablePackageReference() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-61",
			Name:        "Vulnerable Package Reference",
			Description: "Dependencies on open source frameworks and packages introduce additional vulnerabilities into the runtime environment. Vulnerabilities in open source libraries are continuously discovered and documented in publicly available vulnerability databases. Attackers can recognize a package being used by an application, and leverage known vulnerabilities in the library to attack the application. For more information checkout the CWE-937 (https://cwe.mitre.org/data/definitions/937.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`<package id="bootstrap" version="3\.0\.0" targetFramework="net462"/>`),
		},
	}
}

func NewCorsAllowOriginWildCard() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-62",
			Name:        "Cors Allow Origin Wild Card",
			Description: "Cross-Origin Resource Sharing (CORS) allows a service to disable the browser’s Same-origin policy, which prevents scripts on an attacker-controlled domain from accessing resources and data hosted on a different domain. The CORS Access-Control-Allow-Origin HTTP header specifies the domain with permission to invoke a cross-origin service and view the response data. Configuring the Access-Control-Allow-Origin header with a wildcard (*) can allow code running on an attacker-controlled domain to view responses containing sensitive data. For more information checkout the CWE-942 (https://cwe.mitre.org/data/definitions/942.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`app\.UseCors\(builder => builder\.AllowAnyOrigin\(\)\);`),
		},
	}
}

func NewMissingAntiForgeryTokenAttribute() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-63",
			Name:        "Missing Anti Forgery Token Attribute",
			Description: "Cross Site Request Forgery attacks occur when a victim authenticates to a target web site and then visits a malicious web page. The malicious web page then sends a fake HTTP request (GET, POST, etc.) back to the target website. The victim’s valid authentication cookie from the target web site is automatically included in the malicious request, sent to the target web site, and processed as a valid transaction under the victim’s identity. For more information checkout the CWE-352 (https://cwe.mitre.org/data/definitions/352.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[HttpGet\]|\[HttpPost\]|\[HttpPut\]|\[HttpDelete\])(([^V]|V[^a]|Va[^l]|Val[^i]|Vali[^d]|Valid[^a]|Valida[^t]|Validat[^e]|Validate[^A]|ValidateA[^n]|ValidateAn[^t]|ValidateAnt[^i]|ValidateAnti[^F]|ValidateAntiF[^o]|ValidateAntiFo[^r]|ValidateAntiFor[^g]|ValidateAntiForg[^e]|ValidateAntiForge[^r]|ValidateAntiForger[^y]|ValidateAntiForgery[^T]|ValidateAntiForgeryT[^o]|ValidateAntiForgeryTo[^k]|ValidateAntiForgeryTok[^e]|ValidateAntiForgeryToke[^n])*)(ActionResult)`),
		},
	}
}

func NewUnvalidatedWebFormsRedirect() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-64",
			Name:        "Unvalidated Web Forms Redirect",
			Description: "Passing unvalidated redirect locations to the Response.Redirect method can allow attackers to send users to malicious web sites. This can allow attackers to perform phishing attacks and distribute malware to victims. For more information checkout the CWE-601 (https://cwe.mitre.org/data/definitions/601.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Response\.Redirect\(Request\.QueryString\[".*"\]\)`),
		},
	}
}

func NewIdentityPasswordLockoutDisabled() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-65",
			Name:        "Identity Password Lockout Disabled",
			Description: "Password lockout mechanisms help prevent continuous brute force attacks again user accounts by disabling an account for a period of time after a number of invalid attempts. The ASP.NET Identity SignInManager protects against brute force attacks if the lockout parameter is set to true. For more information checkout the CWE-307 (https://cwe.mitre.org/data/definitions/307.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`CheckPasswordSignInAsync\(.*, .*, false\)`),
		},
	}
}

func NewRawInlineExpression() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-66",
			Name:        "Raw Inline Expression",
			Description: "Data is written to the browser using a raw write: <%= var %>. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Instead of using a raw write, use the inline HTML encoded shortcut (<%: var %>) to automatically HTML encode data before writing it to the browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<\%=.*\%\>`),
		},
	}
}

func NewRawBindingExpression() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-67",
			Name:        "Raw Binding Expression",
			Description: "Data is written to the browser using a raw binding expression: <%# Item.Variable %>. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Instead of using a raw binding expression, use the HTML encoded binding shortcut (<%#: Item.Variable %>) to automatically HTML encode data before writing it to the browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<\%#[^:].*\%\>`),
		},
	}
}

func NewRawWriteLiteralMethod() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-68",
			Name:        "Raw Write Literal Method",
			Description: "Data is written to the browser using the raw WriteLiteral method. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Instead of using the raw WriteLiteral method, use a Razor helper that performs automatic HTML encoding before writing it to the browser. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`WriteLiteral\(`),
		},
	}
}

func NewUnencodedWebFormsProperty() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-69",
			Name:        "Unencoded Web Forms Property",
			Description: "Data is written to the browser using a WebForms property that does not perform output encoding. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). WebForms controls are often found in HTML contexts, but can also appear in other contexts such as JavaScript, HTML Attribute, or URL. Fixing the vulnerability requires the appropriate Web Protection Library (aka AntiXSS) context-specific method to encode the data before setting the WebForms property. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(litDetails\.Text)(([^H]|H[^t]|Ht[^m]|Htm[^l]|Html[^E]|HtmlE[^n]|HtmlEn[^c]|HtmlEnc[^o]|HtmlEnco[^d]|HtmlEncod[^e])*)(;)`),
		},
	}
}

func NewUnencodedLabelText() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-70",
			Name:        "Unencoded Label Text",
			Description: "Data is written to the browser using the raw Label.Text method. This can result in Cross-Site Scripting (XSS) vulnerabilities if the data source is considered untrusted or dynamic (request parameters, database, web service, etc.). Label controls are often found in HTML contexts, but can also appear in other contexts such as JavaScript, HTML Attribute, or URL. Fixing the vulnerability requires the appropriate Web Protection Library (aka AntiXSS) context-specific method to encode the data before setting the Label.Text property. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(lblDetails\.Text)(([^H]|H[^t]|Ht[^m]|Htm[^l]|Html[^E]|HtmlE[^n]|HtmlEn[^c]|HtmlEnc[^o]|HtmlEnco[^d]|HtmlEncod[^e])*)(;)`),
		},
	}
}

func NewWeakRandomNumberGenerator() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-71",
			Name:        "Weak Random Number Generator",
			Description: "The use of a predictable random value can lead to vulnerabilities when used in certain security critical contexts. For more information access: (https://security-code-scan.github.io/#SCS0005) or (https://cwe.mitre.org/data/definitions/338.html).",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new Random\(\)`),
		},
	}
}

func NewWeakRsaKeyLength() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-72",
			Name:        "Weak Rsa Key Length",
			Description: "Due to advances in cryptanalysis attacks and cloud computing capabilities, the National Institute of Standards and Technology (NIST) deprecated 1024-bit RSA keys on January 1, 2011. The Certificate Authority Browser Forum, along with the latest version of all browsers, currently mandates a minimum key size of 2048-bits for all RSA keys. For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new RSACryptoServiceProvider\()(\)|[0-9][^\d]|[0-9]{2}[^\d]|[0-9]{3}[^\d]|[0-1][0-9]{3}[^\d]|20[0-3][0-9]|204[0-7])`),
		},
	}
}

func NewXmlReaderExternalEntityExpansion() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-73",
			Name:        "Xml Reader External Entity Expansion",
			Description: "XML External Entity (XXE) vulnerabilities occur when applications process untrusted XML data without disabling external entities and DTD processing. Processing untrusted XML data with a vulnerable parser can allow attackers to extract data from the server, perform denial of service attacks, and in some cases gain remote code execution. The XmlReaderSettings and XmlTextReader classes are vulnerable to XXE attacks when setting the DtdProcessing property to DtdProcessing.Parse or the ProhibitDtd property to false. To prevent XmlReader XXE attacks, avoid using the deprecated ProhibitDtd property. Set the DtdProcessing property to DtdProcessing.Prohibit. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new\sXmlReaderSettings)(([^P]|P[^r]|Pr[^o]|Pro[^h]|Proh[^i]|Prohi[^b]|Prohib[^i]|Prohibi[^t])*)(})`),
		},
	}
}

func NewLdapInjectionDirectoryEntry() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-CSHARP-74",
			Name:        "Ldap Injection Directory Entry",
			Description: "LDAP Injection vulnerabilities occur when untrusted data is concatenated into a LDAP Path or Filter expression without properly escaping control characters. This can allow attackers to change the meaning of an LDAP query and gain access to resources for which they are not authorized. Fixing the LDAP Injection Directory Entry vulnerability requires untrusted data to be encoded using the appropriate Web Protection Library (aka AntiXSS) LDAP encoding method: Encoder.LdapDistinguishedNameEncode(). For more information checkout the CWE-90 (https://cwe.mitre.org/data/definitions/90.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new\sDirectoryEntry\(.*LDAP.*\{)(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r])*)(;)`),
		},
	}
}
