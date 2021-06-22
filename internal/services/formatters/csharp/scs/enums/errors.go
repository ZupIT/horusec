package enums

import "errors"

var ErrorFailedToBuildProject = errors.New(
	"{SECURITY CODE SCAN} project failed to build. Fix the project issues and try again")
