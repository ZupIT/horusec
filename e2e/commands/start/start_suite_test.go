package start_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestStart(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Start Suite")
}
