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

package javascript

import (
	"regexp"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

func NewNoLogSensitiveInformationInConsole() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-1",
			Name:        "No Log Sensitive Information in console",
			Description: "The App logs information. Sensitive information should never be logged. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)((console|log|debug).*\.(log|error|write|warn|clear|table|group|custom|info|debug)\()`),
		},
	}
}

func NewNoUseEval() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-2",
			Name:        "No use eval",
			Description: "The eval function is extremely dangerous. Because if any user input is not handled correctly and passed to it, it will be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion). For more information checkout the CWE-94 (https://cwe.mitre.org/data/definitions/94.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`eval\(((.*[\+,$].*\))|([a-zA-Z]*\)))`),
		},
	}
}

func NewNoDisableTlsRejectUnauthorized() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-3",
			Name:        "No disable tls reject unauthorized",
			Description: "If the NODE_TLS_REJECT_UNAUTHORIZED option is disabled, the Node.js server will accept certificates that are self-signed, allowing an attacker to bypass the TLS security layer. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*(?:'|\")*0(?:'|\")`),
		},
	}
}

func NewNoUseMD5Hashing() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-4",
			Name:        "No use MD5 hashing",
			Description: "The MD5 hash algorithm that was used is considered weak. It can also cause hash collisions. It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createHash\((?:'|\")md5(?:'|\")|(?i)md5\()`),
		},
	}
}

func NewNoUseSHA1Hashing() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-5",
			Name:        "No use SAH1 hashing",
			Description: "The SHA1 hash algorithm that was used is considered weak. It can also cause hash collisions. It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(createHash\((?:'|\")sha1(?:'|\")|(?i)sha1\()`),
		},
	}
}

func NewNoUseWeakRandom() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-6",
			Name:        "No use weak random number generator",
			Description: "When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information. As the Math.random() function relies on a weak pseudorandom number generator, this function should not be used for security-critical applications or for protecting sensitive data. In such context, a cryptographically strong pseudorandom number generator (CSPRNG) should be used instead. For more information checkout the CWE-338 (https://cwe.mitre.org/data/definitions/338.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Math\.random\(`),
		},
	}
}

func NewNoReadFileUsingDataFromRequest() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-7",
			Name:        "No read file using data from request",
			Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system. For more information checkout the CWE-35 (https://cwe.mitre.org/data/definitions/35.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.(readFile|readFileSync)\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNoCreateReadStreamUsingDataFromRequest() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-8",
			Name:        "No create read stream using data from request",
			Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system. For more information checkout the CWE-35 (https://cwe.mitre.org/data/definitions/35.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.createReadStream\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewSQLInjectionUsingParams() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-9",
			Name:        "SQL Injection Using params",
			Description: "Passing untreated parameters to queries in the database can cause an injection of SQL / NoSQL. The attacker is able to insert a custom and improper SQL statement through the data entry of an application. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.(find|drop|create|explain|delete|count|bulk|copy).*\n*{.*\n*(\$|)where(?:'|\"|):.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewXMLParsersShouldNotBeVulnerableToXXEAttacks() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-10",
			Name:        "XML parsers should not be vulnerable to XXE attacks",
			Description: "XML specification allows the use of entities that can be internal or external (file system / network access ...) which could lead to vulnerabilities such as confidential file disclosures or SSRFs. For more information checkout the CWE-827 (https://cwe.mitre.org/data/definitions/827.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.parseXmlString\(.*,.*\)`),
		},
	}
}

func NewOriginsNotVerified() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:   "HS-JAVASCRIPT-11",
			Name: "Origins should be verified during cross-origin communications",
			Description: `Browsers allow message exchanges between Window objects of different origins. Because any window can send / receive messages from other window it is important to verify the sender's / receiver's identity: When sending message with postMessage method, the identity's receiver should be defined (the wildcard keyword (*) should not be used).
When receiving message with message event, the sender's identity should be verified using the origin and possibly source properties. For more information checkout the OWASP A2:2017 (https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication) and (https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) advisory.`,
			Severity:   severities.High.ToString(),
			Confidence: confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.postMessage\((\n|.)*,\s*\"\*\"`),
			regexp.MustCompile(`(\.addEventListener\((\s*|.*)\{)(([^\.]|\.[^o]|\.o[^r]|\.or[^i]|\.ori[^g]|\.orig[^i]|\.origi[^n])*)(\}\s*\))`),
		},
	}
}

func NewWeakSSLTLSProtocolsShouldNotBeUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-12",
			Name:        "Weak SSL/TLS protocols should not be used",
			Description: "Older versions of SSL/TLS protocol like \"SSLv3\" have been proven to be insecure. This rule raises an issue when an SSL/TLS context is created with an insecure protocol version (ie: a protocol different from \"TLSv1.2\", \"TLSv1.3\", \"DTLSv1.2\" or \"DTLSv1.3\"). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`TLSv1_method|TLSv1\.1`),
		},
	}
}

func NewWebSQLDatabasesShouldNotBeUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:   "HS-JAVASCRIPT-13",
			Name: "Web SQL databases should not be used",
			Description: `The Web SQL Database standard never saw the light of day. It was first formulated, then deprecated by the W3C and was only implemented in some browsers. (It is not supported in Firefox or IE.)

Further, the use of a Web SQL Database poses security concerns, since you only need its name to access such a database. For more information checkout the OWSAP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) and A9:2017 (https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html) advisory.`,
			Severity:   severities.High.ToString(),
			Confidence: confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`window\.openDatabase\(`),
		},
	}
}

func NewLocalStorageShouldNotBeUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-14",
			Name:        "Local storage should not be used",
			Description: "Session storage and local storage are HTML 5 features which allow developers to easily store megabytes of data client-side, as opposed to the 4Kb cookies can accommodate. While useful to speed applications up on the client side, it can be dangerous to store sensitive information this way because the data is not encrypted by default and any script on the page may access it. This rule raises an issue when the localStorage and sessionStorage API's are used. For more information checkout the OWSAP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severities.Info.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`localStorage\.setItem\(`),
			regexp.MustCompile(`sessionStorage\.setItem\(`),
		},
	}
}

func NewDebuggerStatementsShouldNotBeUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-15",
			Name:        "Debugger statements should not be used",
			Description: "The debugger statement can be placed anywhere in procedures to suspend execution. Using the debugger statement is similar to setting a breakpoint in the code. By definition such statement must absolutely be removed from the source code to prevent any unexpected behavior or added vulnerability to attacks in production. For more information checkout the CWE-489 (https://cwe.mitre.org/data/definitions/489.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`debugger`),
		},
	}
}

func NewAlertStatementsShouldNotBeUsed() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-16",
			Name:        "Alert statements should not be used",
			Description: "alert(...) as well as confirm(...) and prompt(...) can be useful for debugging during development, but in production mode this kind of pop-up could expose sensitive information to attackers, and should never be displayed. For more information checkout the CWE-489 (https://cwe.mitre.org/data/definitions/489.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?m)(?i)(^||;)(alert|confirm|prompt)\(.*`),
		},
	}
}

func NewStaticallyServingHiddenFilesIsSecuritySensitive() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-17",
			Name:        "Statically serving hidden files is security-sensitive",
			Description: "Hidden files are created automatically by many tools to save user-preferences, well-known examples are .profile, .bashrc, .bash_history or .git. To simplify the view these files are not displayed by default using operating system commands like ls. Outside of the user environment, hidden files are sensitive because they are used to store privacy-related information or even hard-coded secrets. For more information checkout the CWE-538 (https://cwe.mitre.org/data/definitions/538.html) and OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`dotfiles.*allow`),
		},
	}
}

func NewUsingIntrusivePermissionsWithGeolocation() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:   "HS-JAVASCRIPT-18",
			Name: "Using intrusive permissions With Geolocation",
			Description: `Powerful features are browser features (geolocation, camera, microphone ...) that can be accessed with JavaScript API and may require a permission granted by the user. These features can have a high impact on privacy and user security thus they should only be used if they are really necessary to implement the critical parts of an application.

This rule highlights intrusive permissions when requested with the future standard (but currently experimental) web browser query API and specific APIs related to the permission. It is highly recommended to customize this rule with the permissions considered as intrusive in the context of the web application. If geolocation is required, always explain to the user why the application needs it and prefer requesting an approximate location when possible. For more information checkout the CWE-250 (https://cwe.mitre.org/data/definitions/250.html) and OWASP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.`,
			Severity:   severities.Info.ToString(),
			Confidence: confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`permissions\.query\(.*geolocation`),
			regexp.MustCompile(`geolocation\.getCurrentPosition\(`),
		},
	}
}

func NewHavingAPermissiveCrossOriginResourceSharingPolicy() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-19",
			Name:        "Having a permissive Cross-Origin Resource Sharing policy",
			Description: "Same origin policy in browsers prevents, by default and for security-reasons, a javascript frontend to perform a cross-origin HTTP request to a resource that has a different origin (domain, protocol, or port) from its own. The requested target can append additional HTTP headers in response, called CORS, that act like directives for the browser and change the access control policy / relax the same origin policy. The Access-Control-Allow-Origin header should be set only for a trusted origin and for specific resources. For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Access-Control-Allow-Origin["|'|:][\s|,][\s|"|']['|"|\*]['|"|\*]\D`),
			regexp.MustCompile(`cors\(\)`),
			regexp.MustCompile(`origin\s*:\s*['|"]\*['|"]`),
		},
	}
}

func NewReadingTheStandardInput() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-20",
			Name:        "Reading the Standard Input",
			Description: "It is common for attackers to craft inputs enabling them to exploit software vulnerabilities. Thus any data read from the standard input (stdin) can be dangerous and should be validated. Sanitize all data read from the standard input before using it. For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`process\.stdin.read\(\)`),
			regexp.MustCompile(`process\.stdin`),
		},
	}
}

func NewUsingCommandLineArguments() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-21",
			Name:        "Using command line arguments",
			Description: "Command line arguments can be dangerous just like any other user input. They should never be used without being first validated and sanitized. Remember also that any user can retrieve the list of processes running on a system, which makes the arguments provided to them visible. Thus passing sensitive information via command line arguments should be considered as insecure. This rule raises an issue when on every program entry points (main methods) when command line arguments are used. The goal is to guide security code reviews. Sanitize all command line arguments before using them. For more information checkout the CWE-88 (https://cwe.mitre.org/data/definitions/88.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(console|(?i)log|exec|spawn).(.|\n)*process.argv`),
		},
	}
}

func NewRedirectToUnknownPath() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-22",
			Name:        "Redirect to unknown path",
			Description: "Sanitizing untrusted URLs is an important technique for preventing attacks such as request forgeries and malicious redirections. Often, this is done by checking that the host of a URL is in a set of allowed hosts. For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`redirect\((?:\w)`),
		},
	}
}

func NewNoRenderContentFromRequest() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-23",
			Name:        "No render content from request",
			Description: "Directly using user-controlled objects as arguments to template engines might allow an attacker to do local file reads or even remote code execution. For more information checkout the CWE-73 (https://cwe.mitre.org/data/definitions/73.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.render\(.*(?:req\.|req\.query|req\.body|req\.param)`),
			regexp.MustCompile(`\.send\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNoWriteOnDocumentContentFromRequest() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-24",
			Name:        "No write content from request on HTML",
			Description: "Directly writing  messages to a webpage without sanitization allows for a cross-site scripting vulnerability if parts of the message can be influenced by a user. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(document\.write|element\.write|body\.write)\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNoExposeStackTrace() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-25",
			Name:        "Stack trace exposure",
			Description: "Software developers often add stack traces to error messages, as a debugging aid. Whenever that error message occurs for an end user, the developer can use the stack trace to help identify how to fix the problem. For more information checkout the CWE-209 (https://cwe.mitre.org/data/definitions/209.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(res\.end|res\.send)\(.*(?:req\.|e\.stack|error\.stack|err\.stack)`),
		},
	}
}

func NewInsecureDownload() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-26",
			Name:        "Insecure download of executable file",
			Description: "Downloading executables or other sensitive files over an unencrypted connection can leave a server open to man-in-the-middle attacks (MITM). Such an attack can allow an attacker to insert arbitrary content into the downloaded file, and in the worst case, allow the attacker to execute arbitrary code on the vulnerable system.. For more information checkout the CWE-829 (https://cwe.mitre.org/data/definitions/829.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(fetch|get|download)*\(.*(?:http:).*.(\.sh|\.exe|\.cmd|\.bat|\.dll|\.txt)`),
		},
	}
}

func NewNoUseRequestMethodUsingDataFromRequestOfUserInput() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-27",
			Name:        "No use request method using data from request of user input",
			Description: "Allows user input data to be used as parameters for the 'request' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/918.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`require\((?:'|\")request(?:'|\")\)|from\s.request.`),
			regexp.MustCompile(`request\(.*(req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNoUseGetMethodUsingDataFromRequestOfUserInput() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-28",
			Name:        "No use .get method using data from request of user input",
			Description: "Allows user input data to be used as parameters for the 'request.get' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain. For more information checkout the CWE-918 (https://cwe.mitre.org/data/definitions/918.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.get\(.*(req\.|req\.query|req\.body|req\.param)`),
			regexp.MustCompile(`require\((?:'|\")request(?:'|\")\)|from\s.request.`),
		},
	}
}

func NewCryptographicRsaShouldBeRobust() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-29",
			Name:        "Cryptographic RSA should be robust",
			Description: "Most of cryptographic systems require a sufficient key size to be robust against brute-force attacks. n ≥ 2048 for RSA (n is the key length). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(modulusLength:\s*)([0-9][^\d]|[0-9]{2}[^\d]|[0-9]{3}[^\d]|[0-1][0-9]{3}[^\d]|20[0-3][0-9]|204[0-7])`),
			regexp.MustCompile(`\.generateKeyPairSync\(.*rsa`),
		},
	}
}

func NewCryptographicEcShouldBeRobust() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-30",
			Name:        "Cryptographic EC should be robust",
			Description: "Most of cryptographic systems require a sufficient key size to be robust against brute-force attacks. n ≥ 224 for ECDH and ECMQV (Examples: secp192r1 is a non-compliant curve (n < 224) but secp224k1 is compliant (n >= 224)). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(namedCurve:.*secp)([0-9][^\d]|[0-9]{2}[^\d]|[0-2][0-2][0-3][^\d])`),
			regexp.MustCompile(`\.generateKeyPairSync\(.*ec`),
		},
	}
}

func NewJWTNeedStrongCipherAlgorithms() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-31",
			Name:        "JWT should be signed and verified with strong cipher algorithms",
			Description: "If a JSON Web Token (JWT) is not signed with a strong cipher algorithm (or not signed at all) an attacker can forge it and impersonate user identities. Don't use none algorithm to sign or verify the validity of an algorithm. Don't use a token without verifying its signature before. For more information checkout the CWE-347 (https://cwe.mitre.org/data/definitions/347.html) advisory.",
			Severity:    severities.Critical.ToString(),
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

func NewServerHostnameNotVerified() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-32",
			Name:        "Server hostnames should be verified during SSL/TLS connections",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used.  For more information checkout the CWE-297 (https://cwe.mitre.org/data/definitions/297.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`checkServerIdentity.*\{\s*\}`),
			regexp.MustCompile(`(\.request\(|request\.|\.connect\()`),
		},
	}
}

func NewServerCertificatesNotVerified() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-33",
			Name:        "Server certificates should be verified during SSL/TLS connections",
			Description: "To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it's essential to make sure the server presents the right certificate. The certificate's hostname-specific data should match the server hostname. It's not recommended to re-invent the wheel by implementing custom hostname verification. TLS/SSL libraries provide built-in hostname verification functions that should be used.  For more information checkout the CWE-297 (https://cwe.mitre.org/data/definitions/297.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`rejectUnauthorized.*false`),
			regexp.MustCompile(`(\.request\(|request\.|\.connect\()`),
		},
	}
}

func NewUntrustedContentShouldNotBeIncluded() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-34",
			Name:        "Untrusted content should not be included",
			Description: "Including content in your site from an untrusted source can expose your users to attackers and even compromise your own site. For that reason, this rule raises an issue for each non-relative URL. For more information checkout the OWASP A1:2017 (https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html) advisory.",
			Severity:    severities.High.ToString(),
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

func NewMysqlHardCodedCredentialsSecuritySensitive() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-35",
			Name:        "Mysql Hard-coded credentials are security-sensitive",
			Description: "Because it is easy to extract strings from an application source code or binary, credentials should not be hard-coded. This is particularly true for applications that are distributed or that are open-source. It's recommended to customize the configuration of this rule with additional credential words such as \"oauthToken\", \"secret\", others. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
			Severity:    severities.Critical.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(host|user|database|password|port):\s*["|']\w+["|']`),
			regexp.MustCompile(`mysql\.createConnection\(`),
		},
	}
}

func NewUsingShellInterpreterWhenExecutingOSCommands() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-36",
			Name:        "Using shell interpreter when executing OS commands",
			Description: "Arbitrary OS command injection vulnerabilities are more likely when a shell is spawned rather than a new process, indeed shell meta-chars can be used (when parameters are user-controlled for instance) to inject OS commands. For more information checkout the CWE-78 (https://cwe.mitre.org/data/definitions/78.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\.exec\(|\.execSync\(|\.spawn\(|\.spawnSync\(|\.execFile\(|\.execFileSync\()((.*,(.|\s)*shell\s*:\strue)|(("|')?(\w|\s)+("|')?[^,]\))|(.*,.*\{)(([^s]|s[^h]|sh[^e]|she[^l]|shel[^l])*)(\}))`),
			regexp.MustCompile(`child_process`),
		},
	}
}

func NewForwardingClientIPAddress() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-37",
			Name:        "Forwarding client IP address",
			Description: "Users often connect to web servers through HTTP proxies. Proxy can be configured to forward the client IP address via the X-Forwarded-For or Forwarded HTTP headers. IP address is a personal information which can identify a single user and thus impact his privacy. For more information checkout the CWE-78 (https://cwe.mitre.org/data/definitions/78.html) advisory.",
			Severity:    severities.Low.ToString(),
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

func NewAllowingConfidentialInformationToBeLoggedWithSignale() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-38",
			Name:        "Allowing confidential information to be logged with signale",
			Description: "Log management is an important topic, especially for the security of a web application, to ensure user activity, including potential attackers, is recorded and available for an analyst to understand what's happened on the web application in case of malicious activities. Retention of specific logs for a defined period of time is often necessary to comply with regulations such as GDPR, PCI DSS and others. However, to protect user's privacy, certain informations are forbidden or strongly discouraged from being logged, such as user passwords or credit card numbers, which obviously should not be stored or at least not in clear text. For more information checkout the CWE-532 (https://cwe.mitre.org/data/definitions/532.html) advisory.",
			Severity:    severities.Low.ToString(),
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

func NewAllowingBrowsersToPerformDNSPrefetching() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-39",
			Name:        "Allowing browsers to perform DNS prefetching",
			Description: "By default, web browsers perform DNS prefetching to reduce latency due to DNS resolutions required when an user clicks links from a website page. It can add significant latency during requests, especially if the page contains many links to cross-origin domains. DNS prefetch allows web browsers to perform DNS resolving in the background before the user clicks a link. This feature can cause privacy issues because DNS resolving from the user's computer is performed without his consent if he doesn't intent to go to the linked website. On a complex private webpage, a combination \"of unique links/DNS resolutions\" can indicate, to a eavesdropper for instance, that the user is visiting the private page. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severities.Low.ToString(),
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

func NewDisablingCertificateTransparencyMonitoring() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-40",
			Name:        "Disabling Certificate Transparency monitoring",
			Description: "Certificate Transparency (CT) is an open-framework to protect against identity theft when certificates are issued. Certificate Authorities (CA) electronically sign certificate after verifying the identify of the certificate owner. Attackers use, among other things, social engineering attacks to trick a CA to correctly verifying a spoofed identity/forged certificate. CAs implement Certificate Transparency framework to publicly log the records of newly issued certificates, allowing the public and in particular the identity owner to monitor these logs to verify that his identify was not usurped. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`expectCt\s*:\s*false`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewDisablingStrictHTTPNoReferrerPolicy() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-41",
			Name:        "Disabling strict HTTP no-referrer policy",
			Description: "Confidential information should not be set inside URLs (GET requests) of the application and a safe (ie: different from unsafe-url or no-referrer-when-downgrade) referrer-Policy header, to control how much information is included in the referer header, should be used. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severities.Low.ToString(),
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

func NewAllowingBrowsersToSniffMIMETypes() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-42",
			Name:        "Allowing browsers to sniff MIME types",
			Description: "Implement X-Content-Type-Options header with nosniff value (the only existing value for this header) which is supported by all modern browsers and will prevent browsers from performing MIME type sniffing, so that in case of Content-Type header mismatch, the resource is not interpreted. For example within a <script> object context, JavaScript MIME types are expected (like application/javascript) in the Content-Type header. For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`noSniff\s*:\s*false`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewDisablingContentSecurityPolicyFrameAncestorsDirective() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-43",
			Name:        "Disabling content security policy frame-ancestors directive",
			Description: "Clickjacking attacks occur when an attacker try to trick an user to click on certain buttons/links of a legit website. This attack can take place with malicious HTML frames well hidden in an attacker website. Implement content security policy frame-ancestors directive which is supported by all modern browsers and will specify the origins of frame allowed to be loaded by the browser (this directive deprecates X-Frame-Options). For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severities.Low.ToString(),
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

func NewAllowingMixedContent() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-44",
			Name:        "Allowing mixed-content",
			Description: "A mixed-content is when a resource is loaded with the HTTP protocol, from a website accessed with the HTTPs protocol, thus mixed-content are not encrypted and exposed to MITM attacks and could break the entire level of protection that was desired by implementing encryption with the HTTPs protocol. Implement content security policy block-all-mixed-content directive which is supported by all modern browsers and will block loading of mixed-contents. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severities.Low.ToString(),
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

func NewDisablingContentSecurityPolicyFetchDirectives() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-45",
			Name:        "Disabling content security policy fetch directives",
			Description: "Content security policy (CSP) (fetch directives) is a W3C standard which is used by a server to specify, via a http header, the origins from where the browser is allowed to load resources. It can help to mitigate the risk of cross site scripting (XSS) attacks and reduce privileges used by an application. If the website doesn't define CSP header the browser will apply same-origin policy by default. Implement content security policy fetch directives, in particular default-src directive and continue to properly sanitize and validate all inputs of the application, indeed CSP fetch directives is only a tool to reduce the impact of cross site scripting attacks. For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`contentSecurityPolicy\s*:\s*false`),
			regexp.MustCompile(`helmet`),
		},
	}
}

func NewCreatingCookiesWithoutTheHttpOnlyFlag() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-46",
			Name:        "Creating cookies without the \"HttpOnly\" flag",
			Description: "When a cookie is configured with the HttpOnly attribute set to true, the browser guaranties that no client-side script will be able to read it. In most cases, when a cookie is created, the default value of HttpOnly is false and it's up to the developer to decide whether or not the content of the cookie can be read by the client-side script. As a majority of Cross-Site Scripting (XSS) attacks target the theft of session-cookies, the HttpOnly attribute can help to reduce their impact as it won't be possible to exploit the XSS vulnerability to steal session-cookies. By default the HttpOnly flag should be set to true for most of the cookies and it's mandatory for session / sensitive-security cookies. For more information checkout the OWASP A7:2017 (https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`httpOnly\s*:\s*false`),
			regexp.MustCompile(`cookieSession\(|session\(|.set\(|csrf\(`),
		},
	}
}

func NewCreatingCookiesWithoutTheSecureFlag() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-47",
			Name:        "Creating cookies without the \"secure\" flag",
			Description: "When a cookie is protected with the secure attribute set to true it will not be send by the browser over an unencrypted HTTP request and thus cannot be observed by an unauthorized person during a man-in-the-middle attack. It is recommended to use HTTPs everywhere so setting the secure flag to true should be the default behaviour when creating cookies. For more information checkout the OWASP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.AndMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`secure\s*:\s*false`),
			regexp.MustCompile(`cookieSession\(|session\(|.set\(|csrf\(`),
		},
	}
}

func NewNoUseSocketManually() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-48",
			Name:        "No use socket manually",
			Description: "Sockets are vulnerable in multiple ways: They enable a software to interact with the outside world. As this world is full of attackers it is necessary to check that they cannot receive sensitive information or inject dangerous input.The number of sockets is limited and can be exhausted. Which makes the application unresponsive to users who need additional sockets. In many cases there is no need to open a socket yourself. Use instead libraries and existing protocols For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new.*Socket\(`),
			regexp.MustCompile(`require\(.net.\)|from\s.net.`),
		},
	}
}

func NewEncryptionAlgorithmsWeak() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-49",
			Name:        "Encryption Algorithms Weak",
			Description: "To perform secure cryptography, operation modes and padding scheme are essentials and should be used correctly according to the encryption algorithm:For block cipher encryption algorithms (like AES), the GCM (Galois Counter Mode) mode that works internally with zero/no padding scheme, is recommended. At the opposite, these modes and/or schemes are highly discouraged:Electronic Codebook (ECB) mode is vulnerable because it doesn't provide serious message confidentiality: under a given key any given plaintext block always gets encrypted to the same ciphertext block.Cipher Block Chaining (CBC) with PKCS#5 padding (or PKCS#7) is vulnerable to padding oracle attacks.RSA encryption algorithm should be used with the recommended padding scheme (OAEP). More specifically for block cipher, it's not recommended to use algorithm with a block size inferior than 128 bits. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.createCipheriv\(.*(AES-([0-9][^\d]|[0-9]{2}[^\d]|[0-1][0-9]{2}[^\d]|2[0-5][0-5][^\d]))`),
			regexp.MustCompile(`\.createCipheriv\(.*(DES|DES-EDE|DES-EDE3|RC2|RC4|BF)`),
		},
	}
}

func NewFileUploadsShouldBeRestricted() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-50",
			Name:        "File uploads should be restricted",
			Description: "These minimum restrictions should be applied when handling file uploads: the file upload folder to restrict untrusted files to a specific folder. the file extension of the uploaded file to prevent remote code execution. Also the size of the uploaded file should be limited to prevent denial of service attacks. For more information checkout the CWE-434 (https://cwe.mitre.org/data/definitions/434.html) advisory.",
			Severity:    severities.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sFormidable\(\)(.|\n)*(uploadDir.*=.*(["|']\s*["|']|null|undefined))`),
			regexp.MustCompile(`new\sFormidable\(\)(.|\n)*(keepExtensions.*=.*true)`),
			regexp.MustCompile(`(\.diskStorage\(\s*\{)(([^d]|d[^e]|de[^s]|des[^t]|dest[^i]|desti[^n]|destin[^a]|destina[^t]|destinat[^i]|destinati[^o]|destinatio[^n]|destination[^:])*)(\}\s*\))`),
		},
	}
}

func NewAllowingRequestsWithExcessiveContentLengthSecurity() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-51",
			Name:        "Allowing requests with excessive content length is security-sensitive",
			Description: "Rejecting requests with significant content length is a good practice to control the network traffic intensity and thus resource consumption in order to prevents DoS attacks, In your multer by default is no limit and maximum accept in Formidable and multer is 8mb. Ask Yourself Whether: Size limits are not defined for the different resources of the web application? The web application is not protected by rate limiting features? The web application infrastructure has limited resources? There is a risk if you answered yes to any of those questions. For more information checkout the CWE-770 (https://cwe.mitre.org/data/definitions/770.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new\sFormidable(.|\n)*)maxFileSize\s*=\s*([8-9][0-9]{6}|[1-9][0-9]{6}[0-9]+)`),
			regexp.MustCompile(`(multer(.|\n)*)fileSize\s*:\s*([8-9][0-9]{6}|[1-9][0-9]{6}[0-9]+)`),
			regexp.MustCompile(`(multer\(\s*\{)(([^f]|f[^i]|fi[^l]|fil[^e]|file[^S]|fileS[^i]|fileSi[^z]|fileSiz[^e])*)(\}\s*\))`),
		},
	}
}

func NewNoDisableSanitizeHtml() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-52",
			Name:        "No Disable Sanitize Html",
			Description: "To reduce the risk of cross-site scripting attacks, templating systems, such as Twig, Django, Smarty, Groovy's template engine, allow configuration of automatic variable escaping before rendering templates. When escape occurs, characters that make sense to the browser (eg: <a>) will be transformed/replaced with escaped/sanitized values (eg: & lt;a& gt; ). Enable auto-escaping by default and continue to review the use of inputs in order to be sure that the chosen auto-escaping strategy is the right one. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severities.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Mustache.escape`),
			regexp.MustCompile(`(?i)(Handlebars)?\.compile(.|\s)*noEscape`),
			regexp.MustCompile(`(?i)(markdownIt|markdown-it)(.|\s)*html.*true`),
			regexp.MustCompile(`(?i)(marked)?\.setOptions(.|\s)*sanitize.*false`),
			regexp.MustCompile(`(?i)(kramed)?\.Renderer(.|\s)*sanitize.*false`),
		},
	}
}

func NewSQLInjection() *text.Rule {
	return &text.Rule{
		Metadata: engine.Metadata{
			ID:          "HS-JAVASCRIPT-53",
			Name:        "SQL Injection",
			Description: "SQL queries often need to use a hardcoded SQL string with a dynamic parameter coming from a user request. Formatting a string to add those parameters to the request is a bad practice as it can result in an SQL injection. The safe way to add parameters to a SQL query is to use SQL binding mechanisms. For more information checkout the CWE-564 (https://cwe.mitre.org/data/definitions/564.html) and OWASP A1:2017 (https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html) advisory.",
			Severity:    severities.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)query\(.*(SELECT|UPDATE|DELETE|INSERT).*(\+|\$\{)`),
			regexp.MustCompile(`(?i)((?:var|let|const)?\s*\w+.?\s*(=|:).*(SELECT|UPDATE|DELETE|INSERT).*(\+|\$\{)\s*\w+$)`),
		},
	}
}
