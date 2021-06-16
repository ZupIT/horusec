package entities

import (
	"fmt"
	"strings"
)

type Rule struct {
	ID              string  `json:"id"`
	FullDescription Message `json:"fullDescription"`
	HelpURI         string  `json:"helpUri"`
}

func (r *Rule) getFullDescription() string {
	fullDescription := strings.ReplaceAll(r.FullDescription.Text, "{", "")
	fullDescription = strings.ReplaceAll(fullDescription, "}", "")
	return fullDescription
}

func (r *Rule) GetDescription(vulnName string) string {
	return fmt.Sprintf("%s\n%s For more information, check the following url (%s).",
		vulnName, r.getFullDescription(), r.HelpURI)
}
