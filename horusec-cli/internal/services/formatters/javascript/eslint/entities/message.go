package entities

type Message struct {
	RuleID    string `json:"ruleId"`
	Severity  int    `json:"severity"`
	Message   string `json:"message"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	NodeType  string `json:"nodeType"`
	MessageID string `json:"messageId"`
	EndLine   int    `json:"endLine"`
	EndColumn int    `json:"endColumn"`
}
