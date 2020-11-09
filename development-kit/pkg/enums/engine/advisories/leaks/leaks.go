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
package leaks

import (
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/engine/advisories/leaks/regular"
)

func AllRulesLeaksRegular() []text.TextRule {
	return []text.TextRule{
		regular.NewLeaksRegularAWSManagerID(),
		regular.NewLeaksRegularAWSSecretKey(),
		regular.NewLeaksRegularAWSMWSKey(),
		regular.NewLeaksRegularFacebookSecretKey(),
		regular.NewLeaksRegularFacebookClientID(),
		regular.NewLeaksRegularTwitterSecretKey(),
		regular.NewLeaksRegularTwitterClientID(),
		regular.NewLeaksRegularGithub(),
		regular.NewLeaksRegularLinkedInClientID(),
		regular.NewLeaksRegularLinkedInSecretKey(),
		regular.NewLeaksRegularSlack(),
		regular.NewLeaksRegularAsymmetricPrivateKey(),
		regular.NewLeaksRegularGoogleAPIKey(),
		regular.NewLeaksRegularGoogleGCPServiceAccount(),
		regular.NewLeaksRegularHerokuAPIKey(),
		regular.NewLeaksRegularMailChimpAPIKey(),
		regular.NewLeaksRegularMailgunAPIKey(),
		regular.NewLeaksRegularPayPalBraintreeAccessToken(),
		regular.NewLeaksRegularPicaticAPIKey(),
		regular.NewLeaksRegularSendGridAPIKey(),
		regular.NewLeaksRegularStripeAPIKey(),
		regular.NewLeaksRegularSquareAccessToken(),
		regular.NewLeaksRegularSquareOAuthSecret(),
		regular.NewLeaksRegularTwilioAPIKey(),
		regular.NewLeaksRegularHardCodedCredentialGeneric(),
		regular.NewLeaksRegularHardCodedPassword(),
		regular.NewLeaksRegularPasswordExposedInHardcodedURL(),
		regular.NewLeaksRegularWPConfig(),
	}
}

func AllRulesLeaksAnd() []text.TextRule {
	return []text.TextRule{}
}

func AllRulesLeaksOr() []text.TextRule {
	return []text.TextRule{}
}
