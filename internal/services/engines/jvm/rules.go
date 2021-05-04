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

package jvm

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/internal/services/engines/jvm/and"
	"github.com/ZupIT/horusec/internal/services/engines/jvm/or"
	"github.com/ZupIT/horusec/internal/services/engines/jvm/regular"
)

type Interface interface {
	GetAllRules(rules []engine.Rule) []engine.Rule
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules(rules []engine.Rule) []engine.Rule {
	for _, rule := range allRulesJvmAnd() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesJvmOr() {
		rules = append(rules, rule)
	}

	for _, rule := range allRulesJvmRegular() {
		rules = append(rules, rule)
	}

	return rules
}

func allRulesJvmRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewJvmRegularHTTPRequestsConnectionsAndSessions(),
		regular.NewJvmRegularNoUsesSafetyNetAPI(),
		regular.NewJvmRegularNoUsesContentProvider(),
		regular.NewJvmRegularNoUseWithUnsafeBytes(),
		regular.NewJvmRegularNoUseLocalFileIOOperations(),
		regular.NewJvmRegularWebViewComponent(),
		regular.NewJvmRegularEncryptionAPI(),
		regular.NewJvmRegularKeychainAccess(),
		regular.NewJvmRegularNoUseProhibitedAPIs(),
		regular.NewJvmRegularApplicationAllowMITMAttacks(),
		regular.NewJvmRegularUIWebViewInApplicationIgnoringErrorsSSL(),
		regular.NewJvmRegularNoListClipboardChanges(),
		regular.NewJvmRegularApplicationUsingSQLite(),
		regular.NewJvmRegularNoUseNSTemporaryDirectory(),
		regular.NewJvmRegularNoCopiesDataToTheClipboard(),
		regular.NewJvmRegularNoLogSensitiveInformation(),
	}
}

func allRulesJvmAnd() []text.TextRule {
	return []text.TextRule{
		and.NewJvmAndNoDownloadFileUsingAndroidDownloadManager(),
		and.NewJvmAndSQLInjectionWithSQLite(),
		and.NewJvmAndAndroidKeystore(),
		and.NewJvmAndWebViewGETRequest(),
		and.NewJvmAndWebViewPOSTRequest(),
		and.NewJvmAndAndroidNotifications(),
		and.NewJvmAndBase64Decode(),
		and.NewJvmAndPotentialAndroidSQLInjection(),
		and.NewJvmAndKeychainAccess(),
		and.NewJvmAndWebViewLoadRequest(),
		and.NewJvmAndCookieStorage(),
		and.NewJvmAndSetReadClipboard(),
		and.NewJvmAndUsingLoadHTMLStringCanResultInject(),
		and.NewJvmAndNoUseSFAntiPiracyJailbreak(),
		and.NewJvmAndNoUseSFAntiPiracyIsPirated(),
		and.NewJvmAndWeakMd5HashUsing(),
		and.NewJvmAndWeakSha1HashUsing(),
		and.NewJvmAndWeakECBEncryptionAlgorithmUsing(),
		and.NewJvmAndUsingPtrace(),
	}
}

func allRulesJvmOr() []text.TextRule {
	return []text.TextRule{
		or.NewJvmOrSuperUserPrivileges(),
		or.NewJvmOrSendSMS(),
		or.NewJvmOrBase64Encode(),
		or.NewJvmOrGpsLocation(),
		or.NewJvmOrApplicationMayContainJailbreakDetectionMechanisms(),
	}
}
