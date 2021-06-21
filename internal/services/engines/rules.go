package engines

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
)

// RuleManager is a generic implementation of formatters.RuleManager
// that can be reused between all engines to load rules
type RuleManager struct {
	rules      []engine.Rule
	extensions []string
}

func NewRuleManager(rules []engine.Rule, extensions []string) *RuleManager {
	return &RuleManager{
		rules:      rules,
		extensions: extensions,
	}
}

func (r *RuleManager) GetAllRules() []engine.Rule {
	return r.rules
}

//nolint:gomnd // magic number
func (r *RuleManager) GetTextUnitByRulesExt(src string) ([]engine.Unit, error) {
	textUnits, err := text.LoadDirIntoMultiUnit(src, 5, r.extensions)
	if err != nil {
		return []engine.Unit{}, err
	}
	return r.parseTextUnitsToUnits(textUnits), nil
}

func (r *RuleManager) parseTextUnitsToUnits(textUnits []text.TextUnit) []engine.Unit {
	units := make([]engine.Unit, 0, len(textUnits))
	for _, t := range textUnits {
		units = append(units, t)
	}
	return units
}
