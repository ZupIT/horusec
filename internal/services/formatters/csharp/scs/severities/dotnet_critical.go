package severities

import "github.com/ZupIT/horusec-devkit/pkg/enums/severities"

const (
	HardcodedPassword = "SCS0015"
)

func MapCriticalValues() map[string]severities.Severity {
	return map[string]severities.Severity{
		HardcodedPassword: severities.Critical,
	}
}
