package engine

import (
	"fmt"
)

type Location struct {
	Filename string
	Line     int
	Column   int
}

func (location Location) String() string {
	return fmt.Sprintf("Name: %s Location: %d:%d", location.Filename, location.Line, location.Column)
}
