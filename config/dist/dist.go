package dist

const False = "false"

var (
	standAlone string = False
)

func IsStandAlone() bool {
	return standAlone != False
}

func GetVersion() string {
	if IsStandAlone() {
		return "stand-alone"
	}

	return "normal"
}
