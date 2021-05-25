package dist

var (
	standAlone = "false"
)

func IsStandAlone() bool {
	return standAlone != "false"
}

func GetVersion() string {
	if IsStandAlone() {
		return "stand-alone"
	}

	return "normal"
}
