package start_test

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ZupIT/horusec/internal/utils/testutil"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("running binary Horusec with start parameter", func() {
	var (
		args              []string
		session           *gexec.Session
		outBuffer         *gbytes.Buffer
		err               error
		pathBinaryHorusec string
	)

	BeforeEach(func() {
		args = []string{"start"}
	})

	JustBeforeEach(func() {
		pathBinaryHorusec = testutil.GomegaBuildHorusecBinary()
		outBuffer = gbytes.NewBuffer()
		cmd := exec.Command(pathBinaryHorusec, args...)
		session, err = gexec.Start(cmd, GinkgoWriter, outBuffer)

	})

	When("--project-path is passed", func() {
		BeforeEach(func() {
			AnalyzePath := filepath.Join(".")

			flags := map[string]string{
				"-p": AnalyzePath,
			}
			for flag, value := range flags {
				args = append(args, fmt.Sprintf("%s=%s", flag, value))
			}
		})

		It("Then the following validations are performed", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(session.Wait(40 * time.Second).Out.Contents()).To(ContainSubstring("In this analysis, a total of"))
			Eventually(session).Should(gexec.Exit(0))
		})
	})

	When("--analysis-timeout is passed", func() {
		BeforeEach(func() {
			flags := map[string]string{
				"-t": "500",
			}
			for flag, value := range flags {
				args = append(args, fmt.Sprintf("%s=%s", flag, value))
			}
		})

		It("Then the following validations are performed", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(session.Wait(40 * time.Second).Out.Contents()).To(ContainSubstring("Horusec will return a timeout after 500 seconds."))
			Eventually(session).Should(gexec.Exit(0))
		})
	})
})
