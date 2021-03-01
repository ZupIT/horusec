package severities

import "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"

const (
	HardcodedPassword = "SCS0015"
)

func MapCriticalValues() map[string]severity.Severity {
	return map[string]severity.Severity{
		HardcodedPassword: severity.Critical,
	}
}
