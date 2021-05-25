package dist

var (
	StandAlone = false
)

func IsStandAlone() bool {
	return StandAlone
}

func GetDistName() string {
	if IsStandAlone() {
		return "stand-alone"
	}

	return "normal"
}
