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
			ID:          "7fefbb75-2c16-4651-ab8f-3bff4d4e1b78",
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
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(DES.Create\(\))(([^A]|A[^e]|Ae[^s]|Aes[^M]|AesM[^a]|AesMa[^n]|AesMan[^a]|AesMana[^g]|AesManag[^e]|AesManage[^d])*)(Write\(.*\))`),
		},
	}
}
