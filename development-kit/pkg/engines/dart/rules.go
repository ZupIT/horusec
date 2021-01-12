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
package dart

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/dart/and"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/dart/or"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/dart/regular"
)

type Interface interface {
	GetAllRules() []engine.Rule
	GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error)
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules() (rules []engine.Rule) {
	for _, rule := range allRulesDartAnd() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesDartOr() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesDartRegular() {
		rules = append(rules, rule)
	}

	return rules
}

func allRulesDartRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewDartRegularXSSAttack(),
		regular.NewDartRegularNoLogSensitive(),
		regular.NewDartRegularWeakHashingFunctionMd5OrSha1(),
		regular.NewDartRegularNoUseSelfSignedCertificate(),
	}
}

func allRulesDartAnd() []text.TextRule {
	return []text.TextRule{
		and.NewDartAndUsageLocalDataWithoutCryptography(),
		and.NewDartAndNoSendSensitiveInformation(),
	}
}

func allRulesDartOr() []text.TextRule {
	return []text.TextRule{
		or.NewDartOrNoUseConnectionWithoutSSL(),
	}
}

func (r *Rules) GetTextUnitByRulesExt(projectPath string) ([]engine.Unit, error) {
	textUnit, err := text.LoadDirIntoSingleUnit(projectPath, r.getExtensions())
	return []engine.Unit{textUnit}, err
}

func (r *Rules) getExtensions() []string {
	return []string{".dart"}
}

/*
#### https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage
[x] XSS attacks

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage
[x] use of insecure local data
  - SQL databases
  - Log files
  - XML ​​data storage or manifest files
  - Binary data stores
  - Cookie shops
  - SD card
  - Synchronized cloud.

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication
[X] Do not use a connection without SSL
[X] Do not use a badly configured SSL connection
[ ] Do not send confidential data through alternative channels (SMS, MMS, Notifications)
[X] Best practices for iOS
  - Check that the certificates are valid
  - When using CFNetwork Make sure that NSStreamSocketSecurityLevelTLSv1 is being used to increase the standard encoding strength
  - Remove the option setAllowsAnyHTTPSCertificate to avoid using self-signed certificates
[X] Best practices for Android
  - Remove the org.apache.http.conn.ssl.AllowAllHostnameVerifier or SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER options to prevent you from using self-signed certificates
  - If you are using a class that extends SSLSocketFactory, make sure that the checkServerTrusted method is implemented correctly so that the server certificate is verified correctly

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication
[ ] Saving local data as token passwords and more can leave a security hole
[ ] Use of TouchID can have insecure authentication

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography
[x] Use of low encryption

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m6-insecure-authorization
[ ] Presence of Insecure Direct Object Reference (IDOR) vulnerabilities
[ ] Hidden end points
[ ] Client-side user role or permission transmissions

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality
[ ] C buffer overflow
[ ] DOM-based XSS

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering
[ ] Check if the code has been tampered with in real time of execution
  - Check that build.prop includes the line ro.build.tags = test-keys indicating a developer build or unofficial ROM
  - Check for OTA certificates
  - Check that the /etc/security/otacerts.zip file exists
  - Check for several well-known root APKs
    - com.noshufou.android.su
    - com.thirdparty.superuser
    - eu.chainfire.supersu
    - com.koushikdutta.superuser
  - Check the SU binaries
    - / system / bin / su
    - / system / xbin / su
    - / sbin / su
    - / system / su
    - /system/bin/.ext/.su
  - Try the SU command directly and check the current user id, if it returns 0 then the su command was successful

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m9-reverse-engineering
[ ] Use an obfuscation tool to prevent reverse engineering.

#### https://owasp.org/www-project-mobile-top-10/2016-risks/m10-extraneous-functionality
[ ] Examine the application's configuration settings to discover any hidden switches;
[ ] Check that all the test code is not included in the final production version of the application;
[ ] Examine all API endpoints accessed by the mobile application to verify that these endpoints are well documented and publicly available;
[ ] Examine all logging instructions to ensure that nothing too descriptive about the backend is being written to the logs;
*/
