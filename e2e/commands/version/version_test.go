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

package version_test

import (
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

var _ = Describe("Run horusec CLI with version argument", func() {
	var (
		outBuffer *gbytes.Buffer
		session   *gexec.Session
		err       error
	)

	BeforeEach(func() {
		binaryPath := testutil.GomegaBuildHorusecBinary()
		outBuffer = gbytes.NewBuffer()
		session, err = gexec.Start(exec.Command(binaryPath, "version"), outBuffer, outBuffer)
	})

	It("execute command without error", func() {
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(session).Should(gexec.Exit(0))
	})

	It("displays current version", func() {
		Eventually(session).Should(gexec.Exit(0))
		Eventually(outBuffer).Should(gbytes.Say("Version:          vTest"))
	})
})
