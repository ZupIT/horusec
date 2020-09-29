package engine

// UnitType defines which type of content, and therefore, which kind of rule
// is needed in order to extract information about the program we are analyzing
type UnitType int

const (
	ProgramTextUnit UnitType = iota
)

// Rule defines a generic rule for any kind of analysis the engine have to execute
type Rule interface {
	IsFor(UnitType) bool // Indicates which kind of program unit this rules can be ran on
}

// Metadata holds information for the rule to match a useful advisory
type Metadata struct {
	ID          string
	Name        string
	CodeSample  string
	Description string

	// Metadata levels
	Severity   string
	Confidence string
}
