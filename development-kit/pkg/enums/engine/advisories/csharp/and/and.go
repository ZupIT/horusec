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
package and

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewCsharpAndCommandInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "782ad071-1cf3-4230-936f-b7a1e794828d",
			Name:        "Command Injection",
			Description: "If a malicious user controls either the FileName or Arguments, he might be able to execute unwanted commands or add unwanted argument. This behavior would not be possible if input parameter are validate against a white-list of characters. For more information access: (https://security-code-scan.github.io/#SCS0001).",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndXPathInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "010a99b2-9f35-4cb3-9209-248bacba07f8",
			Name:        "XPath Injection",
			Description: "If the user input is not properly filtered, a malicious user could extend the XPath query. For more information access: (https://security-code-scan.github.io/#SCS0003).",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndExternalEntityInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f3390c7e-8151-4f8a-8bc4-433841569153",
			Name:        "XML eXternal Entity Injection (XXE)",
			Description: "The XML parser is configured incorrectly. The operation could be vulnerable to XML eXternal Entity (XXE) processing. For more information access: (https://security-code-scan.github.io/#SCS0007).",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndPathTraversal() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3b905eb5-5af7-41db-a234-38c934f675b2",
			Name:        "Path Traversal",
			Description: "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the expected directory.By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files. For more information access: (https://security-code-scan.github.io/#SCS0018).",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndSQLInjectionWebControls() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "b6f82b7c-f321-4651-8ad3-87fbf5e0412b",
			Name:        "SQL Injection WebControls",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database. For more information access: (https://security-code-scan.github.io/#SCS0014).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`"Select .* From .* where .*" & .*`),
			regexp.MustCompile(`System\.Web\.UI\.WebControls\.SqlDataSource | System\.Web\.UI\.WebControls\.SqlDataSourceView | Microsoft\.Whos\.Framework\.Data\.SqlUtility`),
		},
	}
}

func NewCsharpAndWeakCipherOrCBCOrECBMode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f9436bdd-8a80-4168-98fa-17af9f8c51b8",
			Name:        "Weak Cipher Mode",
			Description: "The cipher provides no way to detect that the data has been tampered with. If the cipher text can be controlled by an attacker, it could be altered without detection. The use of AES in CBC mode with a HMAC is recommended guaranteeing integrity and confidentiality. For more information access: (https://security-code-scan.github.io/#SCS0013).",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndFormsAuthenticationCookielessMode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "81f4b46e-164c-478f-ad3a-df263d73c00c",
			Name:        "Forms Authentication Cookieless Mode",
			Description: "Authentication cookies should not be sent in the URL. Doing so allows attackers to gain unauthorized access to authentication tokens (web server logs, referrer headers, and browser history) and more easily perform session fixation / hijacking attacks. For more information checkout the CWE-598 (https://cwe.mitre.org/data/definitions/598.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<authentication\s*mode\s*=\s*["|']Forms`),
			regexp.MustCompile(`(\<forms)((([^c]|c[^o]|co[^o]|coo[^k]|cook[^i]|cooki[^e]|cookie[^l]|cookiel[^e]|cookiele[^s]|cookieles[^s])*)|([^U]|U[^s]|Us[^e]|Use[^C]|UseC[^o]|UseCo[^o]|UseCoo[^k]|UseCook[^i]|UseCooki[^e]|UseCookie[^s])*)(\/\>)`),
		},
	}
}

func NewCsharpAndFormsAuthenticationCrossAppRedirects() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "05cd1279-54a7-4770-9527-3ecd6c83b167",
			Name:        "Forms Authentication Cross App Redirects",
			Description: "Enabling cross-application redirects can allow unvalidated redirect attacks via the returnUrl parameter during the login process. Disable cross-application redirects to by setting the enableCrossAppRedirects attribute to false. For more information checkout the CWE-601 (https://cwe.mitre.org/data/definitions/601.html) advisory.",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndFormsAuthenticationWeakCookieProtection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "97df49ee-1043-4158-ba33-efed0ac3a28d",
			Name:        "Forms Authentication Weak Cookie Protection",
			Description: "Forms Authentication cookies must use strong encryption and message authentication code (MAC) validation to protect the cookie value from inspection and tampering. Configure the forms element’s protection attribute to All to enable cookie data validation and encryption. For more information checkout the CWE-565 (https://cwe.mitre.org/data/definitions/565.html) advisory.",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndFormsAuthenticationWeakTimeout() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "fc00e79f-03ae-43eb-967f-46d8b6efa2ea",
			Name:        "Forms Authentication Weak Timeout",
			Description: "Excessive authentication timeout values provide attackers with a large window of opportunity to hijack user’s authentication tokens. For more information checkout the CWE-613 (https://cwe.mitre.org/data/definitions/613.html) advisory.",
			Severity:    severity.Medium.ToString(),
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

func NewCsharpAndHeaderCheckingDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "64d27b88-8729-4867-af26-d22989b9a430",
			Name:        "Header Checking Disabled",
			Description: "Disabling the HTTP Runtime header checking protection opens the application up to HTTP Header Injection (aka Response Splitting) attacks. Enable the header checking protection by setting the httpRuntime element’s enableHeaderChecking attribute to true, which is the default value. For more information checkout the CWE-113 (https://cwe.mitre.org/data/definitions/113.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<httpRuntime`),
			regexp.MustCompile(`enableHeaderChecking\s*=\s*["|']false`),
		},
	}
}

func NewCsharpAndVersionHeaderEnabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9a27a481-7bed-4577-8c77-f799998e6527",
			Name:        "Version Header Enabled",
			Description: "The Version HTTP response header sends the ASP.NET framework version to the client’s browser. This information can help an attacker identify vulnerabilities in the server’s framework version and should be disabled in production. Disable the version response header by setting the httpRuntime element’s enableVersionHeader attribute to false. For more information checkout the CWE-200 (https://cwe.mitre.org/data/definitions/200.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<httpRuntime`),
			regexp.MustCompile(`enableVersionHeader\s*=\s*["|']true`),
		},
	}
}

func NewCsharpAndEventValidationDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "466cbe65-504f-4983-8fc1-0e0a8b05c27c",
			Name:        "Event Validation Disabled",
			Description: "Event validation prevents unauthorized post backs in web form applications. Disabling this feature can allow attackers to forge requests from controls not visible or enabled on a given web form. Enable event validation by setting the page element’s eventValidation attribute to true. For more information checkout the CWE-807 (https://cwe.mitre.org/data/definitions/807.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<pages`),
			regexp.MustCompile(`enableEventValidation\s*=\s*["|']false`),
		},
	}
}

func NewCsharpAndWeakSessionTimeout() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "7a2f543f-3e61-4538-9d44-d1bfec183fcd",
			Name:        "Weak Session Timeout",
			Description: "If session data is used by the application for authentication, excessive timeout values provide attackers with a large window of opportunity to hijack user’s session tokens. Configure the session timeout value to meet your organization’s timeout policy. For more information checkout the CWE-613 (https://cwe.mitre.org/data/definitions/613.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<sessionState`),
			regexp.MustCompile(`timeout\s*=\s*["|'](1[6-9]|[2-9][0-9]*)`),
		},
	}
}

func NewCsharpAndStateServerMode() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "e93d9c0f-a0cb-4246-8318-38246e2b930a",
			Name:        "Weak Session Timeout",
			Description: "The session StateServer mode transports session data insecurely to a remote server. The remote server also does not require system authentication to access the session data for an application. This risk depends entirely on the sensitivity of the data stored in the user’s session. If the session data is considered sensitive, consider adding an external control (e.g. IPSEC) that provides mutual authentication and transport security. For more information checkout the CWE-319 (https://cwe.mitre.org/data/definitions/319.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<sessionState`),
			regexp.MustCompile(`mode\s*=\s*["|']StateServer`),
		},
	}
}

func NewCsharpAndJwtSignatureValidationDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "07b30a32-b3af-4e70-b043-25853cfdda09",
			Name:        "Jwt Signature Validation Disabled",
			Description: "Web service APIs relying on JSON Web Tokens (JWT) for authentication and authorization must sign each JWT with a private key or secret. Each web service endpoint must require JWT signature validation prior to decoding and using the token to access protected resources. The values RequireExpirationTime, RequireSignedTokens, ValidateLifetime can't was false. For more information checkout the CWE-347 (https://cwe.mitre.org/data/definitions/347.html) and CWE-613 (https://cwe.mitre.org/data/definitions/613.html) advisory.",
			Severity:    severity.High.ToString(),
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

func NewCsharpAndInsecureHttpCookieTransport() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ebb18250-9b55-4ceb-8cd3-25feb7d7dccd",
			Name:        "Insecure Http Cookie Transport",
			Description: "Cookies containing authentication tokens, session tokens, and other state management credentials must be protected in transit across a network. Set the cookie options’ Secure property to true to prevent the browser from transmitting cookies over HTTP. For more information checkout the CWE-614 (https://cwe.mitre.org/data/definitions/614.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sCookieOptions\(\)`),
			regexp.MustCompile(`Secure\s*=\s*false`),
		},
	}
}

func NewCsharpAndHttpCookieAccessibleViaScript() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8eb27f89-d56a-4ef6-939f-92a3eedc074c",
			Name:        "Http Cookie Accessible Via Script",
			Description: "Cookies containing authentication tokens, session tokens, and other state management credentials should be protected from malicious JavaScript running in the browser. Setting the httpOnly attribute to false can allow attackers to inject malicious scripts into the site and extract authentication cookie values to a remote server. Configure the cookie options’ httpOnly property to true, which prevents cookie access from scripts running in the browser. For more information checkout the CWE-1004 (https://cwe.mitre.org/data/definitions/1004.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sCookieOptions\(\)`),
			regexp.MustCompile(`HttpOnly\s*=\s*false`),
		},
	}
}

func NewCsharpAndDirectoryListingEnabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1b7219b8-230b-4f4d-a4b3-00126b0278dc",
			Name:        "Directory Listing Enabled",
			Description: "Directory listing provides a complete index of the resources located in a web directory. Enabling directory listing can expose sensitive resources such as application binaries, configuration files, and static content that should not be exposed. Unless directory listing is required to meet the application’s functional requirements, disable the listing by setting the directoryBrowse element’s enabled attribute to false. For more information checkout the CWE-548 (https://cwe.mitre.org/data/definitions/548.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\<directoryBrowse`),
			regexp.MustCompile(`enabled\s*=\s*['|"]true`),
		},
	}
}

func NewCsharpAndLdapAuthenticationDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f325388e-b6a9-4c48-b304-adf274af95c7",
			Name:        "Ldap Authentication Disabled",
			Description: "Disabling LDAP Authentication configures insecure connections to the backend LDAP provider. Using the DirectoryEntry AuthenticationType property’s Anonymous or None option allows an anonymous or basic authentication connection to the LDAP provider. Set the the DirectoryEntry AuthenticationType property to Secure, which requests Kerberos authentication under the security context of the calling thread or as a provider username and password. For more information checkout the CWE-287 (https://cwe.mitre.org/data/definitions/287.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sDirectoryEntry\(.*\)`),
			regexp.MustCompile(`AuthenticationTypes.Anonymous`),
		},
	}
}

func NewCsharpAndCertificateValidationDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4b6fb420-5e89-494f-86d5-4501cedb4921",
			Name:        "Certificate Validation Disabled",
			Description: "Disabling certificate validation is common in testing and development environments. Quite often, this is accidentally deployed to production, leaving the application vulnerable to man-in-the-middle attacks on insecure networks. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new WebRequestHandler\(\)`),
			regexp.MustCompile(`ServerCertificateValidationCallback \+= \(.*\) => true;`),
		},
	}
}

func NewCsharpAndActionRequestValidationDisabled() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d70bc47b-19f3-4ae3-b262-b5131993a341",
			Name:        "Action Request Validation Disabled",
			Description: "Request validation performs blacklist input validation for XSS payloads found in form and URL request parameters. Request validation has known bypass issues and does not prevent all XSS attacks, but it does provide a strong countermeasure for most payloads targeting a HTML context. For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\[HttpGet\(.*\)\]|\[HttpPost\(.*\)\]|\[HttpPut\(.*\)\]|\[HttpDelete\(.*\)\]|\[HttpGet\]|\[HttpPost\]|\[HttpPut\]|\[HttpDelete\])`),
			regexp.MustCompile(`\[ValidateInput\(false\)\]`),
		},
	}
}

func NewCsharpAndXmlDocumentExternalEntityExpansion() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ee650d6d-683a-4b8d-bdb3-c85a74385bf6",
			Name:        "Xml Document External Entity Expansion",
			Description: "XML External Entity (XXE) vulnerabilities occur when applications process untrusted XML data without disabling external entities and DTD processing. Processing untrusted XML data with a vulnerable parser can allow attackers to extract data from the server, perform denial of service attacks, and in some cases gain remote code execution. The XmlDocument class is vulnerable to XXE attacks when setting the XmlResolver property to resolve external entities. To prevent XmlDocument XXE attacks, set the XmlResolver property to null. For more information checkout the CWE-611 (https://cwe.mitre.org/data/definitions/611.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sXmlDocument`),
			regexp.MustCompile(`(XmlResolver)(([^n]|n[^u]|nu[^l]|nul[^l])*)(;)`),
		},
	}
}
