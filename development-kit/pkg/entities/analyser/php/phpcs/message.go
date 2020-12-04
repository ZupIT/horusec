package phpcs

import (
	"strconv"
	"strings"
)

type Message struct {
	Message string `json:"message"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Type    string `json:"type"`
}

func (m *Message) GetLine() string {
	return strconv.Itoa(m.Line)
}

func (m *Message) GetColumn() string {
	return strconv.Itoa(m.Column)
}

func (m *Message) IsValidMessage() bool {
	return m.Type == "ERROR" &&
		!strings.Contains(m.Message, "This implies that some PHP code is not scanned by PHPCS")
}
