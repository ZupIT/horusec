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

package generate_test

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

var _ = Describe("Run horusec CLI with generate argument", func() {
	var (
		outBuffer      = gbytes.NewBuffer()
		errBuffer      = gbytes.NewBuffer()
		session        *gexec.Session
		err            error
		flags          map[string]string
		configFilePath string
	)

	BeforeSuite(func() {
		configFileName := "horusec-config-generate-test.json"
		configFilePath = filepath.Join(os.TempDir(), configFileName)
		// Add scape slashes when running on Windows.
		configFilePath = strings.ReplaceAll(configFilePath, `\`, `\\`)
	})

	BeforeEach(func() {
		flags = map[string]string{
			"--config-file-path": configFilePath,
		}
		cmd := testutil.GinkgoGetHorusecCmdWithFlags(testutil.GenerateCmd, flags)
		session, err = gexec.Start(cmd, outBuffer, errBuffer)
	})

	AfterEach(func() {
		_ = outBuffer.Clear()
		_ = errBuffer.Clear()
	})

	When("the horusec-config.json still doesn't exists", func() {
		BeforeEach(func() {
			_ = os.Remove(configFilePath)
		})

		It("execute command without error", func() {
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
		})

		It("show success message and correct path of config file", func() {
			Eventually(outBuffer).Should(gbytes.Say(`Horusec created file of configuration with success on path:`))
			Eventually(outBuffer).Should(gbytes.Say(fmt.Sprintf("[%s]", configFilePath)))
		})
	})

	When("the horusec-config.json already exists", func() {
		It("execute command without error", func() {
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
		})

		It("show message already exists", func() {
			Eventually(outBuffer).Should(gbytes.Say(`Horusec configuration already exists on path:`))
			Eventually(outBuffer).Should(gbytes.Say(fmt.Sprintf("[%s]", configFilePath)))
		})
	})
})
