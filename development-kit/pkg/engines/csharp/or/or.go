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
package or

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"regexp"
)

func NewCsharpOrLDAPInjection() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "236724c0-482a-47f4-ba10-7ae14f47fd7b",
			Name:        "LDAP Injection",
			Description: "The dynamic value passed to the LDAP query should be validated. For more information access: (https://security-code-scan.github.io/#SCS0031).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(new DirectorySearcher\(\))(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r]|Encoder[^.]|Encoder\.[^L]|Encoder\.L[^d]|Encoder\.Ld[^a]|Encoder\.Lda[^p]|Encoder\.Ldap[^F]|Encoder\.LdapF[^i]|Encoder\.LdapFi[^l]|Encoder\.LdapFil[^t]|Encoder\.LdapFilt[^e]|Encoder\.LdapFilte[^r]|Encoder\.LdapFilter[^E]|Encoder\.LdapFilterE[^n]|Encoder\.LdapFilterEn[^c]|Encoder\.LdapFilterEnc[^o]|Encoder\.LdapFilterEnco[^d]|Encoder\.LdapFilterEncod[^e])*)(\)";)`),
			regexp.MustCompile(`(new DirectoryEntry\(\))(([^E]|E[^n]|En[^c]|Enc[^o]|Enco[^d]|Encod[^e]|Encode[^r]|Encoder[^.]|Encoder\.[^L]|Encoder\.L[^d]|Encoder\.Ld[^a]|Encoder\.Lda[^p]|Encoder\.Ldap[^D]|Encoder\.LdapD[^i]|Encoder\.LdapDi[^s]|Encoder\.LdapDis[^t]|Encoder\.LdapDist[^i]|Encoder\.LdapDisti[^n]|Encoder\.LdapDistin[^g]|Encoder\.LdapDisting[^u]|Encoder\.LdapDistingu[^i]|Encoder\.LdapDistingui[^s]|Encoder\.LdapDistinguis[^h]|Encoder\.LdapDistinguish[^e]|Encoder\.LdapDistinguishe[^d]|Encoder\.LdapDistinguished[^N]|Encoder\.LdapDistinguishedN[^a]|Encoder\.LdapDistinguishedNa[^m]|Encoder\.LdapDistinguishedNam[^e]|Encoder\.LdapDistinguishedName[^E]|Encoder\.LdapDistinguishedNameE[^n]|Encoder\.LdapDistinguishedNameEn[^c]|Encoder\.LdapDistinguishedNameEnc[^o]|Encoder\.LdapDistinguishedNameEnco[^d]|Encoder\.LdapDistinguishedNameEncod[^e])*)(,.*";)`),
		},
	}
}

func NewCsharpOrSQLInjectionLinq() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "64cd7acd-99a8-4640-a2eb-ca839c47040d",
			Name:        "SQL Injection LINQ",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database.. For more information access: (https://security-code-scan.github.io/#SCS0002).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(var|ExecuteQuery).*(=|\().*(SELECT|UPDATE|DELETE|INSERT).*\++`),
		},
	}
}

func NewCsharpOrInsecureDeserialization() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a5a1dcad-76e7-4d9d-afe4-0dba1bcca105",
			Name:        "Insecure Deserialization",
			Description: "Arbitrary code execution, full application compromise or denial of service. An attacker may pass specially crafted serialized .NET object of specific class that will execute malicious code during the construction of the object. For more information access: (https://security-code-scan.github.io/#SCS0028).",
			Severity:    severity.Low.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`new\sBinaryFormatter\(\)\.Deserialize\(.*\)`),
			regexp.MustCompile(`new\sJavaScriptSerializer\(..*\)`),
		},
	}
}

func NewCsharpOrSQLInjectionEnterpriseLibraryData() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "0ea39e22-de31-4888-9348-58f4170755fd",
			Name:        "SQL Injection Enterprise Library Data",
			Description: "Arbitrary code execution, full application compromise or denial of service. An attacker may pass specially crafted serialized .NET object of specific class that will execute malicious code during the construction of the object. For more information access: (https://security-code-scan.github.io/#SCS0036).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(GetSqlStringCommand\(.*\))(([^A]|A[^d]|Ad[^d]|Add[^I]|AddI[^n]|AddIn[^P]|AddInP[^a]|AddInPa[^r]|AddInPar[^a]|AddInPara[^m]|AddInParam[^e]|AddInParame[^t]|AddInParamet[^e]|AddInParamete[^r])*)(ExecuteDataSet\(.*\))`),
			regexp.MustCompile(`ExecuteDataSet\(CommandType.*, "(SELECT|select).*(FROM|from).*(WHERE|where).*"\)`),
		},
	}
}

func NewCsharpOrCQLInjectionCassandra() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "56dbcac5-f61b-4ad0-bcf3-214bca83b172",
			Name:        "CQL Injection Cassandra",
			Description: "Arbitrary code execution, full application compromise or denial of service. An attacker may pass specially crafted serialized .NET object of specific class that will execute malicious code during the construction of the object. For more information access: (https://security-code-scan.github.io/#SCS0038).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`(Prepare\("(SELECT|select).*(FROM|from).*(WHERE|where).*\))(([^B]|B[^i]|Bi[^n]|Bin[^d])*)(Execute\(.*\))`),
			regexp.MustCompile(`Execute\("(SELECT|select).*(FROM|from).*(WHERE|where).*"\)`),
		},
	}
}

func NewCsharpOrPasswordComplexity() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "9027bece-7a6f-4e6e-b7e5-5dbbe0870562",
			Name:        "Password Complexity",
			Description: "PasswordValidator should have at least two requirements for better security, the RequiredLength property must be set with a minimum value of 8. For more information access: (https://security-code-scan.github.io/#SCS0027).",
			Severity:    severity.Low.ToString(),
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

func NewCsharpOrCookieWithoutSSLFlag() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "c3c93cc6-f010-42fa-9e13-34dbaf33b852",
			Name:        "Cookie Without SSL Flag",
			Description: "It is recommended to specify the Secure flag to new cookie. The Secure flag is a directive to the browser to make sure that the cookie is not sent by unencrypted channel. For more information access: (https://security-code-scan.github.io/#SCS0008) and (https://cwe.mitre.org/data/definitions/614.html).",
			Severity:    severity.Low.ToString(),
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

func NewCsharpOrCookieWithoutHttpOnlyFlag() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "837c504d-38b4-4ea6-987b-d91e92ac86a2",
			Name:        "Cookie Without HttpOnly Flag",
			Description: "It is recommended to specify the HttpOnly flag to new cookie. For more information access: (https://security-code-scan.github.io/#SCS0009) or (https://cwe.mitre.org/data/definitions/1004.html).",
			Severity:    severity.Low.ToString(),
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

func NewCsharpOrNoInputVariable() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "d5f46985-1527-47b0-a5c1-71c9ab121cf7",
			Name:        "No input variable",
			Description: "The application appears to allow XSS through an unencrypted / unauthorized input variable. https://owasp.org/www-community/attacks/xss/. For more information checkout the CWE-79 (https://cwe.mitre.org/data/definitions/79.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.High.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`\s*var\s+\w+\s*=\s*"\s*\<\%\s*=\s*\w+\%\>";`),
			regexp.MustCompile(`\.innerHTML\s*=\s*.+`),
		},
	}
}

func NewCsharpOrIdentityWeakPasswordComplexity() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "928962a4-0e8c-494d-9e96-771ca9b4863f",
			Name:        "Identity Weak Password Complexity",
			Description: "Weak passwords can allow attackers to easily guess user passwords using wordlist or brute force attacks. Enforcing a strict password complexity policy mitigates these attacks by significantly increasing the time to guess a user’s valid password. For more information checkout the CWE-521 (https://cwe.mitre.org/data/definitions/521.html) advisory.",
			Severity:    severity.High.ToString(),
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
