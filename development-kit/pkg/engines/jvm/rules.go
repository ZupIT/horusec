package jvm

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/jvm/and"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/jvm/or"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/jvm/regular"
)

type Interface interface {
	GetAllRules(rules []engine.Rule) []engine.Rule
}

type Rules struct{}

func NewRules() Interface {
	return &Rules{}
}

func (r *Rules) GetAllRules(rules []engine.Rule) []engine.Rule {
	for index := range allRulesJvmAnd() {
		rules = append(rules, allRulesJvmAnd()[index])
	}

	for index := range allRulesJvmOr() {
		rules = append(rules, allRulesJvmOr()[index])
	}

	for index := range allRulesJvmRegular() {
		rules = append(rules, allRulesJvmRegular()[index])
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
