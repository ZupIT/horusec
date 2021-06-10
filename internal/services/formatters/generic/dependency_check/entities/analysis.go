package entities

type Analysis struct {
	Dependencies []*Dependence `json:"dependencies"`
}
