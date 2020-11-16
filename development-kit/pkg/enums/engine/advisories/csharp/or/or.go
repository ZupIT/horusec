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
			ID:          "32fbdff3-2092-4d42-90a2-784842bebfd0",
			Name:        "SQL Injection LINQ",
			Description: "Malicious user might get direct read and/or write access to the database. If the database is poorly configured the attacker might even get Remote Code Execution (RCE) on the machine running the database.. For more information access: (https://security-code-scan.github.io/#SCS0002).",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.OrMatch,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`ExecuteQuery\(.*SELECT .* FROM .* WHERE .* \+ .* \+ .*\)`),
			regexp.MustCompile(`var .* = "SELECT .* FROM .* WHERE .* \+ .* \+ .*"`),
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
			ID:          "7fefbb75-2c16-4651-ab8f-3bff4d4e1b78",
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
