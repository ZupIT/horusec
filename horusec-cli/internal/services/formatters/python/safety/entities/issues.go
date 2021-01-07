package entities

type Issue struct {
	Dependency       string `json:"dependency"`
	VulnerableBelow  string `json:"vulnerable_below"`
	InstalledVersion string `json:"installed_version"`
	Description      string `json:"description"`
	ID               string `json:"id"`
}
