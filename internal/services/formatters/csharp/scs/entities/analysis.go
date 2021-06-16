package entities

type Analysis struct {
	Runs []*Run `json:"runs"`
}

func (a *Analysis) GetRun() *Run {
	if len(a.Runs) > 0 {
		return a.Runs[0]
	}

	return nil
}

func (a *Analysis) MapVulnerabilitiesByID() map[string]*Rule {
	vulnMap := map[string]*Rule{}

	for _, rule := range a.GetRun().Tool.Driver.Rules {
		vulnMap[rule.ID] = rule
	}

	return vulnMap
}
