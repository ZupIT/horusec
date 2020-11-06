package phases

import (
	"strings"
)

type Phase string

func (p Phase) String() string {
	if p == Release {
		return ""
	}
	return string(p)
}

func (p Phase) IsRelease() bool {
	return p == Release
}

const (
	Alpha            Phase = "alpha"
	Beta             Phase = "beta"
	ReleaseCandidate Phase = "rc"
	Release          Phase = "release"

	Unknown Phase = ""
)

func Values() []Phase {
	return []Phase{
		Alpha,
		Beta,
		ReleaseCandidate,
		Release,
	}
}

func ValueOf(value string) Phase {
	for _, valid := range Values() {
		if IsEqual(value, valid.String()) {
			return valid
		} else if value == "release" {
			return Release
		}
	}

	return Unknown
}

func IsEqual(value, valid string) bool {
	return strings.EqualFold(value, valid)
}

func IndexOf(value Phase) int {
	for i, v := range Values() {
		if v == value {
			return i
		}
	}

	return -1
}
