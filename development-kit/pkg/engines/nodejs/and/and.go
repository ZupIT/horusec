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
	"regexp"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

func NewNodeJSAndNoUseRequestMethodUsingDataFromRequestOfUserInput() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "74736e94-926c-41bc-b4e8-61aad62ba11b",
			Name:        "No use request method using data from request of user input",
			Description: "Allows user input data to be used as parameters for the 'request' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/918.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`require\((?:'|\")request(?:'|\")\)|from\s.request.`),
			regexp.MustCompile(`request\(.*(req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSAndNoUseGetMethodUsingDataFromRequestOfUserInput() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "af548d16-c6d4-46eb-bb35-630cab1c00f1",
			Name:        "No use .get method using data from request of user input",
			Description: "Allows user input data to be used as parameters for the 'request.get' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/918.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.get\(.*(req\.|req\.query|req\.body|req\.param)`),
			regexp.MustCompile(`require\((?:'|\")request(?:'|\")\)|from\s.request.`),
		},
	}
}

func NewNodeJSAndCryptographicRsaShouldBeRobust() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f434338d-0480-4f80-9af0-cd6a3e61f2d1",
			Name:        "Cryptographic RSA should be robust",
			Description: "Most of cryptographic systems require a sufficient key size to be robust against brute-force attacks. n ≥ 2048 for RSA (n is the key length). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(modulusLength:\s*)([0-9][^\d]|[0-9]{2}[^\d]|[0-9]{3}[^\d]|[0-1][0-9]{3}[^\d]|20[0-3][0-9]|204[0-7])`),
			regexp.MustCompile(`\.generateKeyPairSync\(.*rsa`),
		},
	}
}

func NewNodeJSAndCryptographicEcShouldBeRobust() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "4e4bc6ed-9be5-41a6-97f6-34d2b365d8c5",
			Name:        "Cryptographic EC should be robust",
			Description: "Most of cryptographic systems require a sufficient key size to be robust against brute-force attacks. n ≥ 224 for ECDH and ECMQV (Examples: secp192r1 is a non-compliant curve (n < 224) but secp224k1 is compliant (n >= 224)). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(namedCurve:.*secp)([0-9][^\d]|[0-9]{2}[^\d]|[0-2][0-2][0-3][^\d])`),
			regexp.MustCompile(`\.generateKeyPairSync\(.*ec`),
		},
	}
}

func NewNodeJSAndJWTNeedStrongCipherAlgorithms() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f8c6b5bb-2e8c-4e63-9db2-7a075e9fe3fc",
			Name:        "JWT should be signed and verified with strong cipher algorithms",
			Description: "If a JSON Web Token (JWT) is not signed with a strong cipher algorithm (or not signed at all) an attacker can forge it and impersonate user identities. Don't use none algorithm to sign or verify the validity of an algorithm. Don't use a token without verifying its signature before. For more information checkout the CWE-347 (https://cwe.mitre.org/data/definitions/347.html) advisory.",
			Severity:    severity.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`((algorithm[s]?:.*none)|(algorithm[s]?:.*RS256))`),
			regexp.MustCompile(`require\(.jsonwebtoken.\)|from\s.jsonwebtoken.`),
			regexp.MustCompile(`\.sign\(`),
		},
	}
}

func NewNodeJSAndServerHostnameNotVerified() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ff1d81aa-4fa4-4502-b3a4-65743139c0a0",
			Name:        "Server hostnames should be verified during SSL/TLS connections",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used.  For more information checkout the CWE-297 (https://cwe.mitre.org/data/definitions/297.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`checkServerIdentity.*\{\s*\}`),
			regexp.MustCompile(`(\.request\(|request\.|\.connect\()`),
		},
	}
}

func NewNodeJSAndServerCertificatesNotVerified() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "1288d900-98b1-4ab6-8b8a-b6f6143a4ca0",
			Name:        "Server certificates should be verified during SSL/TLS connections",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used.  For more information checkout the CWE-297 (https://cwe.mitre.org/data/definitions/297.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`rejectUnauthorized.*false`),
			regexp.MustCompile(`(\.request\(|request\.|\.connect\()`),
		},
	}
}

func NewNodeJSAndUntrustedContentShouldNotBeIncluded() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9be13831-1147-4b55-b858-c2cbe595f9e4",
			Name:        "Untrusted content should not be included",
			Description: "Including content in your site from an untrusted source can expose your users to attackers and even compromise your own site. For that reason, this rule raises an issue for each non-relative URL. For more information checkout the OWASP A1:2017 (https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`setAttribute\(.src.,\s*[^"|']\w+[^"|']`),
			regexp.MustCompile(`createElement\(`),
			regexp.MustCompile(`setAttribute\(.*,.*text/javascript`),
		},
	}
}

func NewNodeJSAndMysqlHardCodedCredentialsSecuritySensitive() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c25c5d12-1ae0-4d74-bff1-2ccee6548da9",
			Name:        "Mysql Hard-coded credentials are security-sensitive",
			Description: "Because it is easy to extract strings from an application source code or binary, credentials should not be hard-coded. This is particularly true for applications that are distributed or that are open-source. It's recommended to customize the configuration of this rule with additional credential words such as \"oauthToken\", \"secret\", others. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
			Severity:    severity.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(host|user|database|password|port):\s*["|']\w+["|']`),
			regexp.MustCompile(`mysql\.createConnection\(`),
		},
	}
}

func NewNodeJSAndUsingShellInterpreterWhenExecutingOSCommands() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "04b93a07-d0cf-435b-9a3b-54cb5ff22ce6",
			Name:        "Using shell interpreter when executing OS commands",
			Description: "Arbitrary OS command injection vulnerabilities are more likely when a shell is spawned rather than a new process, indeed shell meta-chars can be used (when parameters are user-controlled for instance) to inject OS commands. For more information checkout the CWE-78 (https://cwe.mitre.org/data/definitions/78.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\.exec\(|\.execSync\(|\.spawn\(|\.spawnSync\(|\.execFile\(|\.execFileSync\()((.*,(.|\s)*shell\s*:\strue)|(("|')?(\w|\s)+("|')?[^,]\))|(.*,.*\{)(([^s]|s[^h]|sh[^e]|she[^l]|shel[^l])*)(\}))`),
			regexp.MustCompile(`child_process`),
		},
	}
}

func NewNodeJSAndForwardingClientIPAddress() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3625aaac-d09f-4f57-9bdd-2901882c653f",
			Name:        "Forwarding client IP address",
			Description: "Users often connect to web servers through HTTP proxies. Proxy can be configured to forward the client IP address via the X-Forwarded-For or Forwarded HTTP headers. IP address is a personal information which can identify a single user and thus impact his privacy. For more information checkout the CWE-78 (https://cwe.mitre.org/data/definitions/78.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`xfwd\s*:\s*true`),
			regexp.MustCompile(`http-proxy|http-proxy-middleware`),
			regexp.MustCompile(`\.createProxyServer\(|\.createProxyMiddleware\(`),
		},
	}
}

func NewNodeJSAndAllowingConfidentialInformationToBeLoggedWithSignale() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "81a94577-4874-434d-a8ce-d5c3950df418",
			Name:        "Allowing confidential information to be logged with signale",
			Description: "Log management is an important topic, especially for the security of a web application, to ensure user activity, including potential attackers, is recorded and available for an analyst to understand what's happened on the web application in case of malicious activities. Retention of specific logs for a defined period of time is often necessary to comply with regulations such as GDPR, PCI DSS and others. However, to protect user's privacy, certain informations are forbidden or strongly discouraged from being logged, such as user passwords or credit card numbers, which obviously should not be stored or at least not in clear text. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`secrets\s*:\s*\[\s*\]`),
			regexp.MustCompile(`signale`),
			regexp.MustCompile(`new\sSignale`),
		},
	}
}

func NewNodeJSAndAllowingBrowsersToPerformDNSPrefetching() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "77040aa2-5322-4092-849e-c9448fdea3bc",
			Name:        "Allowing browsers to perform DNS prefetching",
			Description: "By default, web browsers perform DNS prefetching to reduce latency due to DNS resolutions required when an user clicks links from a website page. It can add significant latency during requests, especially if the page contains many links to cross-origin domains. DNS prefetch allows web browsers to perform DNS resolving in the background before the user clicks a link. This feature can cause privacy issues because DNS resolving from the user's computer is performed without his consent if he doesn't intent to go to the linked website. On a complex private webpage, a combination \"of unique links/DNS resolutions\" can indicate, to a eavesdropper for instance, that the user is visiting the private page. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`allow\s*:\s*true`),
			regexp.MustCompile(`dnsPrefetchControl\(`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewNodeJSAndDisablingCertificateTransparencyMonitoring() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f135b762-8647-462a-8b00-1198ece1f972",
			Name:        "Disabling Certificate Transparency monitoring",
			Description: "Certificate Transparency (CT) is an open-framework to protect against identity theft when certificates are issued. Certificate Authorities (CA) electronically sign certificate after verifying the identify of the certificate owner. Attackers use, among other things, social engineering attacks to trick a CA to correctly verifying a spoofed identity/forged certificate. CAs implement Certificate Transparency framework to publicly log the records of newly issued certificates, allowing the public and in particular the identity owner to monitor these logs to verify that his identify was not usurped. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`expectCt\s*:\s*false`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewNodeJSAndDisablingStrictHTTPNoReferrerPolicy() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c575e343-7b3c-4d9d-bbd6-c020641c1fa3",
			Name:        "Disabling strict HTTP no-referrer policy",
			Description: "Confidential information should not be set inside URLs (GET requests) of the application and a safe (ie: different from unsafe-url or no-referrer-when-downgrade) referrer-Policy header, to control how much information is included in the referer header, should be used. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`policy\s*:(\s|.)*no-referrer-when-downgrade`),
			regexp.MustCompile(`\.referrerPolicy\(`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewNodeJSAndAllowingBrowsersToSniffMIMETypes() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "37c047e5-e48b-4346-a1f4-eb128f3c5e16",
			Name:        "Allowing browsers to sniff MIME types",
			Description: "Implement X-Content-Type-Options header with nosniff value (the only existing value for this header) which is supported by all modern browsers and will prevent browsers from performing MIME type sniffing, so that in case of Content-Type header mismatch, the resource is not interpreted. For example within a <script> object context, JavaScript MIME types are expected (like application/javascript) in the Content-Type header. For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`noSniff\s*:\s*false`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewNodeJSAndDisablingContentSecurityPolicyFrameAncestorsDirective() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "295e4212-13f1-4132-beec-1ce4cb025150",
			Name:        "Disabling content security policy frame-ancestors directive",
			Description: "Clickjacking attacks occur when an attacker try to trick an user to click on certain buttons/links of a legit website. This attack can take place with malicious HTML frames well hidden in an attacker website. Implement content security policy frame-ancestors directive which is supported by all modern browsers and will specify the origins of frame allowed to be loaded by the browser (this directive deprecates X-Frame-Options). For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`frameAncestors\s*:(\s|.)*none`),
			regexp.MustCompile(`helmet`),
			regexp.MustCompile(`\.contentSecurityPolicy\(`),
		},
	}
}

func NewNodeJSAndAllowingMixedContent() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "11c90831-d161-4f97-96b0-6e2d45f9ef6d",
			Name:        "Allowing mixed-content",
			Description: "A mixed-content is when a resource is loaded with the HTTP protocol, from a website accessed with the HTTPs protocol, thus mixed-content are not encrypted and exposed to MITM attacks and could break the entire level of protection that was desired by implementing encryption with the HTTPs protocol. Implement content security policy block-all-mixed-content directive which is supported by all modern browsers and will block loading of mixed-contents. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(directives\s*:\s*\{)(([^b]|b[^l]|bl[^o]|blo[^c]|bloc[^k]|block[^A]|blockA[^l]|blockAl[^l]|blockAll[^M]|blockAllM[^i]|blockAllMi[^x]|blockAllMix[^e]|blockAllMixe[^d]|blockAllMixed[^C]|blockAllMixedC[^o]|blockAllMixedCo[^n]|blockAllMixedCon[^t]|blockAllMixedCont[^e]|blockAllMixedConte[^n]|blockAllMixedConten[^t])*)(\})`),
			regexp.MustCompile(`helmet`),
			regexp.MustCompile(`\.contentSecurityPolicy\(`),
		},
	}
}

func NewNodeJSAndDisablingContentSecurityPolicyFetchDirectives() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c4bd82a9-8089-45fe-9b64-017843f98928",
			Name:        "Disabling content security policy fetch directives",
			Description: "Content security policy (CSP) (fetch directives) is a W3C standard which is used by a server to specify, via a http header, the origins from where the browser is allowed to load resources. It can help to mitigate the risk of cross site scripting (XSS) attacks and reduce privileges used by an application. If the website doesn't define CSP header the browser will apply same-origin policy by default. Implement content security policy fetch directives, in particular default-src directive and continue to properly sanitize and validate all inputs of the application, indeed CSP fetch directives is only a tool to reduce the impact of cross site scripting attacks. For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`contentSecurityPolicy\s*:\s*false`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewNodeJSAndCreatingCookiesWithoutTheHttpOnlyFlag() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f65ac143-d2c7-44b8-b7b3-1f33c7cf9a1d",
			Name:        "Creating cookies without the \"HttpOnly\" flag",
			Description: "When a cookie is configured with the HttpOnly attribute set to true, the browser guaranties that no client-side script will be able to read it. In most cases, when a cookie is created, the default value of HttpOnly is false and it's up to the developer to decide whether or not the content of the cookie can be read by the client-side script. As a majority of Cross-Site Scripting (XSS) attacks target the theft of session-cookies, the HttpOnly attribute can help to reduce their impact as it won't be possible to exploit the XSS vulnerability to steal session-cookies. By default the HttpOnly flag should be set to true for most of the cookies and it's mandatory for session / sensitive-security cookies. For more information checkout the OWASP A7:2017 (https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`httpOnly\s*:\s*false`),
			regexp.MustCompile(`cookieSession\(|session\(|.set\(|csrf\(`),
		},
	}
}

func NewNodeJSAndCreatingCookiesWithoutTheSecureFlag() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a60c9e48-4a28-41b7-990e-47a9cf237974",
			Name:        "Creating cookies without the \"secure\" flag",
			Description: "When a cookie is protected with the secure attribute set to true it will not be send by the browser over an unencrypted HTTP request and thus cannot be observed by an unauthorized person during a man-in-the-middle attack. It is recommended to use HTTPs everywhere so setting the secure flag to true should be the default behaviour when creating cookies. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`secure\s*:\s*false`),
			regexp.MustCompile(`cookieSession\(|session\(|.set\(|csrf\(`),
		},
	}
}

func NewNodeJSAndNoUseSocketManually() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "508034eb-660f-4004-a852-aa8a013a6d84",
			Name:        "No use socket manually",
			Description: "Sockets are vulnerable in multiple ways: They enable a software to interact with the outside world. As this world is full of attackers it is necessary to check that they cannot receive sensitive information or inject dangerous input.The number of sockets is limited and can be exhausted. Which makes the application unresponsive to users who need additional sockets. In many cases there is no need to open a socket yourself. Use instead libraries and existing protocols For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new.*Socket\(`),
			regexp.MustCompile(`require\(.net.\)|from\s.net.`),
		},
	}
}
