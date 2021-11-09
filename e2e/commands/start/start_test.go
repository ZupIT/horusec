// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package start_test

import (
	"strings"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

var _ = Describe("running binary Horusec with start parameter", func() {
	var (
		session           *gexec.Session
		err               error
		flags             map[string]string
		repoAuthorization string
		configFilePath    = testutil.GoExample1
	)

	JustBeforeEach(func() {
		cmd := testutil.GinkgoGetHorusecCmdWithFlags(testutil.CmdStart, flags)
		session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder)

		By("runs the command without errors", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(session).Should(gexec.Exit(0))

		})
	})

	When("--project-path is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath: configFilePath,
			}
		})

		It("Checks if the project path was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(strings.ReplaceAll(testutil.GoExample1, `\`, `\\`)))
		})
	})

	When("--analysis-timeout is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:     configFilePath,
				testutil.StartFlagAnalysisTimeout: "500",
			}
		})

		It("Checks if the timeout property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring("Horusec will return a timeout after 500 seconds."))
		})
	})

	When("--authorization is passed", func() {
		BeforeEach(func() {
			repoAuthorization = uuid.New().String()
			flags = map[string]string{
				testutil.StartFlagProjectPath:   configFilePath,
				testutil.StartFlagAuthorization: repoAuthorization,
			}
		})

		It("Checks if the repository authorization property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring("repository_authorization"))
			Expect(session).Should(gbytes.Say(repoAuthorization))
		})
	})
})
