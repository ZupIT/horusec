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
			Severity:    severity.High.ToString(),
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
			Severity:    severity.High.ToString(),
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
			Severity:    severity.High.ToString(),
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
			Severity:    severity.Medium.ToString(),
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
			Severity:    severity.Medium.ToString(),
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
			Description: "By default, web browsers perform DNS prefetching to reduce latency due to DNS resolutions required when an user clicks links from a website page. It can add significant latency during requests, especially if the page contains many links to cross-origin domains. DNS prefetch allows web browsers to perform DNS resolving in the background before the user clicks a link. This feature can cause privacy issues because DNS resolving from the user's computer is performed without his consent if he doesn't intent to go to the linked website. On a complex private webpage, a combination \"of unique links/DNS resolutions\" can indicate, to a eavesdropper for instance, that the user is visiting the private page. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`dnsPrefetchControl\(`),
			regexp.MustCompile(`helmet`),
			regexp.MustCompile(`allow\s*:\s*true`),
		},
	}
}
