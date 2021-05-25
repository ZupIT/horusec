package dist

var (
	StandAlone = false
)

func IsStandAlone() bool {
	return StandAlone
}

func GetVersion() string {
	if IsStandAlone() {
		return "stand-alone"
	}

	return "normal"
}
