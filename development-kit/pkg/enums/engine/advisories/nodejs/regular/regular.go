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
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewNodeJSRegularNoLogSensitiveInformationInConsole() text.TextRule {
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
			regexp.MustCompile(`(?i)((console|log|debug).*\.(log|error|write|warn|clear|table|group|custom|info|debug)\()`),
		},
	}
}

func NewNodeJSRegularNoUseEval() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "458736c7-8b9a-49f5-9102-f36b12b5a6c2",
			Name:        "No use eval",
			Description: "The eval function is extremely dangerous. Because if any user input is not handled correctly and passed to it, it will be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion). For more information checkout the CWE-94 (https://cwe.mitre.org/data/definitions/94.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(eval\(.+)(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularNoDisableTlsRejectUnauthorized() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "eb3a06aa-b8a2-4249-a605-24799b0691c7",
			Name:        "No disable tls reject unauthorized",
			Description: "If the NODE_TLS_REJECT_UNAUTHORIZED option is disabled, the Node.js server will accept certificates that are self-signed, allowing an attacker to bypass the TLS security layer. For more information checkout the CWE-295 (https://cwe.mitre.org/data/definitions/295.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?:\[|)(?:'|\")NODE_TLS_REJECT_UNAUTHORIZED(?:'|\")(?:\]|)\s*=\s*(?:'|\")*0(?:'|\")`),
		},
	}
}

func NewNodeJSRegularNoUseMD5Hashing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6ca794ec-a8bd-48a3-be37-b535069744f8",
			Name:        "No use MD5 hashing",
			Description: "The MD5 hash algorithm that was used is considered weak. It can also cause hash collisions. It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`createHash\((?:'|\")md5(?:'|\")`),
		},
	}
}

func NewNodeJSRegularNoUseSAH1Hashing() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "af6492f1-6b64-45f8-807c-ebf52466e74b",
			Name:        "No use SAH1 hashing",
			Description: "The SHA1 hash algorithm that was used is considered weak. It can also cause hash collisions. It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`createHash\((?:'|\")sha1(?:'|\")`),
		},
	}
}

func NewNodeJSRegularNoUseWeakRandom() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a35afa4b-7fbd-4872-9fe9-c78243f76c9c",
			Name:        "No use weak random number generator",
			Description: "When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information. As the Math.random() function relies on a weak pseudorandom number generator, this function should not be used for security-critical applications or for protecting sensitive data. In such context, a cryptographically strong pseudorandom number generator (CSPRNG) should be used instead. For more information checkout the CWE-338 (https://cwe.mitre.org/data/definitions/338.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Math\.random\(`),
		},
	}
}

func NewNodeJSRegularNoReadFileUsingDataFromRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "6573c53c-88a8-48cd-a118-6866055a72cf",
			Name:        "No read file using data from request",
			Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system. For more information checkout the CWE-35 (https://cwe.mitre.org/data/definitions/35.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.readFile\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularNoCreateReadStreamUsingDataFromRequest() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "3f6700f2-c9b5-49d0-99e6-367a2c75c6ed",
			Name:        "No create read stream using data from request",
			Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system. For more information checkout the CWE-35 (https://cwe.mitre.org/data/definitions/35.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.createReadStream\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularSQLInjectionUsingParams() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "624eda63-cfff-4b5c-b13d-be8c0d5f1fcc",
			Name:        "SQL Injection Using params",
			Description: "Passing untreated parameters to queries in the database can cause an injection of SQL / NoSQL. The attacker is able to insert a custom and improper SQL statement through the data entry of an application. For more information checkout the CWE-89 (https://cwe.mitre.org/data/definitions/89.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.(find|drop|create|explain|delete|count|bulk|copy).*\n*{.*\n*\$where(?:'|\"|):.*(?:req\.|req\.query|req\.body|req\.param)`),
		},
	}
}

func NewNodeJSRegularXMLParsersShouldNotBeVulnerableToXXEAttacks() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8226ed10-a4f0-4683-89a0-2ad782b58340",
			Name:        "XML parsers should not be vulnerable to XXE attacks",
			Description: "XML specification allows the use of entities that can be internal or external (file system / network access ...) which could lead to vulnerabilities such as confidential file disclosures or SSRFs. For more information checkout the CWE-827 (https://cwe.mitre.org/data/definitions/827.html) advisory.",
			Severity:    severity.Medium.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.parseXmlString\(.*,.*\)`),
		},
	}
}

func NewNodeJSRegularOriginsNotVerified() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "340829b4-29cb-42c2-a518-e442feaa71f6",
			Name:        "Origins should be verified during cross-origin communications",
			Description: "Browsers allow message exchanges between Window objects of different origins. Because any window can send / receive messages from other window it is important to verify the sender's / receiver's identity: When sending message with postMessage method, the identity's receiver should be defined (the wildcard keyword (*) should not be used).\nWhen receiving message with message event, the sender's identity should be verified using the origin and possibly source properties. For more information checkout the OWASP A2:2017 (https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication) and (https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\.postMessage\((\n|.)*,\s*\"\*\"`),
			regexp.MustCompile(`(\.addEventListener\((\s*|.*)\{)(([^\.]|\.[^o]|\.o[^r]|\.or[^i]|\.ori[^g]|\.orig[^i]|\.origi[^n])*)(\}\s*\))`),
		},
	}
}

func NewNodeJSRegularWeakSSLTLSProtocolsShouldNotBeUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "820fcaec-629b-47f4-a097-774de6e8b94c",
			Name:        "Weak SSL/TLS protocols should not be used",
			Description: "Older versions of SSL/TLS protocol like \"SSLv3\" have been proven to be insecure. This rule raises an issue when an SSL/TLS context is created with an insecure protocol version (ie: a protocol different from \"TLSv1.2\", \"TLSv1.3\", \"DTLSv1.2\" or \"DTLSv1.3\"). For more information checkout the CWE-326 (https://cwe.mitre.org/data/definitions/326.html) and CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`TLSv1_method|TLSv1\.1`),
		},
	}
}

func NewNodeJSRegularWebSQLDatabasesShouldNotBeUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "ad918008-78a5-4ba4-85f2-e473e56a9b3b",
			Name:        "Web SQL databases should not be used",
			Description: "The Web SQL Database standard never saw the light of day. It was first formulated, then deprecated by the W3C and was only implemented in some browsers. (It is not supported in Firefox or IE.)\n\nFurther, the use of a Web SQL Database poses security concerns, since you only need its name to access such a database. For more information checkout the OWSAP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) and A9:2017 (https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`window\.openDatabase\(`),
		},
	}
}

func NewNodeJSRegularLocalStorageShouldNotBeUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "698a44c8-2baf-495f-8437-5125767e2bbf",
			Name:        "Local storage should not be used",
			Description: "Session storage and local storage are HTML 5 features which allow developers to easily store megabytes of data client-side, as opposed to the 4Kb cookies can accommodate. While useful to speed applications up on the client side, it can be dangerous to store sensitive information this way because the data is not encrypted by default and any script on the page may access it. This rule raises an issue when the localStorage and sessionStorage API's are used. For more information checkout the OWSAP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`localStorage\.setItem\(`),
			regexp.MustCompile(`sessionStorage\.setItem\(`),
		},
	}
}

func NewNodeJSRegularDebuggerStatementsShouldNotBeUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f172aec8-1ced-45c7-a057-310b1ebf23f9",
			Name:        "Debugger statements should not be used",
			Description: "The debugger statement can be placed anywhere in procedures to suspend execution. Using the debugger statement is similar to setting a breakpoint in the code. By definition such statement must absolutely be removed from the source code to prevent any unexpected behavior or added vulnerability to attacks in production. For more information checkout the CWE-489 (https://cwe.mitre.org/data/definitions/489.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`debugger`),
		},
	}
}

func NewNodeJSRegularAlertStatementsShouldNotBeUsed() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "8780d9ea-8b54-4415-b604-d44b8ee29fb7",
			Name:        "Alert statements should not be used",
			Description: "alert(...) as well as confirm(...) and prompt(...) can be useful for debugging during development, but in production mode this kind of pop-up could expose sensitive information to attackers, and should never be displayed. For more information checkout the CWE-489 (https://cwe.mitre.org/data/definitions/489.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(\s+|^)(alert|confirm|prompt)\(`),
		},
	}
}

func NewNodeJSRegularStaticallyServingHiddenFilesIsSecuritySensitive() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "32fbdff3-2092-4d42-90a2-784842bebfd0",
			Name:        "Statically serving hidden files is security-sensitive",
			Description: "Hidden files are created automatically by many tools to save user-preferences, well-known examples are .profile, .bashrc, .bash_history or .git. To simplify the view these files are not displayed by default using operating system commands like ls. Outside of the user environment, hidden files are sensitive because they are used to store privacy-related information or even hard-coded secrets. For more information checkout the CWE-538 (https://cwe.mitre.org/data/definitions/538.html) and OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`dotfiles.*allow`),
		},
	}
}

func NewNodeJSRegularUsingIntrusivePermissionsWithGeolocation() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "37a70026-eb50-4062-86a7-4bd933888cd2",
			Name:        "Using intrusive permissions With Geolocation",
			Description: "Powerful features are browser features (geolocation, camera, microphone ...) that can be accessed with JavaScript API and may require a permission granted by the user. These features can have a high impact on privacy and user security thus they should only be used if they are really necessary to implement the critical parts of an application.\n\nThis rule highlights intrusive permissions when requested with the future standard (but currently experimental) web browser query API and specific APIs related to the permission. It is highly recommended to customize this rule with the permissions considered as intrusive in the context of the web application. If geolocation is required, always explain to the user why the application needs it and prefer requesting an approximate location when possible. For more information checkout the CWE-250 (https://cwe.mitre.org/data/definitions/250.html) and OWASP A3:2017 (https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html) advisory.",
			Severity:    severity.Info.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`permissions\.query\(.*geolocation`),
			regexp.MustCompile(`geolocation\.getCurrentPosition\(`),
		},
	}
}

func NewNodeJSRegularHavingAPermissiveCrossOriginResourceSharingPolicy() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "f27cc667-219e-4066-99cd-b9c5fd3c94d9",
			Name:        "Having a permissive Cross-Origin Resource Sharing policy",
			Description: "Same origin policy in browsers prevents, by default and for security-reasons, a javascript frontend to perform a cross-origin HTTP request to a resource that has a different origin (domain, protocol, or port) from its own. The requested target can append additional HTTP headers in response, called CORS, that act like directives for the browser and change the access control policy / relax the same origin policy. The Access-Control-Allow-Origin header should be set only for a trusted origin and for specific resources. For more information checkout the OWASP A6:2017 (https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Access-Control-Allow-Origin\s*:\s*['|"]\*['|"]`),
			regexp.MustCompile(`cors\(\)`),
			regexp.MustCompile(`origin\s*:\s*['|"]\*['|"]`),
		},
	}
}

func NewNodeJSRegularReadingTheStandardInput() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a07645b9-2d11-43bb-a15e-d5888bffa05c",
			Name:        "Reading the Standard Input",
			Description: "It is common for attackers to craft inputs enabling them to exploit software vulnerabilities. Thus any data read from the standard input (stdin) can be dangerous and should be validated. Sanitize all data read from the standard input before using it. For more information checkout the CWE-20 (https://cwe.mitre.org/data/definitions/20.html) advisory.",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`process\.stdin.read\(\)`),
			regexp.MustCompile(`process\.stdin`),
		},
	}
}

func NewNodeJSRegularUsingCommandLineArguments() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "5b6e321b-0612-481e-86b2-3d8b2854258f",
			Name:        "Using command line arguments",
			Description: "Command line arguments can be dangerous just like any other user input. They should never be used without being first validated and sanitized. Remember also that any user can retrieve the list of processes running on a system, which makes the arguments provided to them visible. Thus passing sensitive information via command line arguments should be considered as insecure. This rule raises an issue when on every program entry points (main methods) when command line arguments are used. The goal is to guide security code reviews. Sanitize all command line arguments before using them. For more information checkout the CWE-88 (https://cwe.mitre.org/data/definitions/88.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(console|(?i)log|exec|spawn).(.|\n)*process.argv`),
		},
	}
}
