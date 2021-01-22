package entities

import "strconv"

type Output struct {
	File string `json:"file"`
	Line int `json:"line"`
	EndLine int `json:"endLine"`
	Column int `json:"column"`
	EndColumn int `json:"endColumn"`
	Level string `json:"level"`
	Code int `json:"code"`
	Message string `json:"message"`
	Fix interface{} `json:"fix"`
}

func (o *Output) GetLine() string {
	return strconv.Itoa(o.Line)
}

func (o *Output) GetColumn() string {
	return strconv.Itoa(o.Column)
}
