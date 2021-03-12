package dto

import (
	"encoding/json"

	severityEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type UpdateVulnSeverity struct {
	Severity severityEnum.Severity `json:"severity"`
}

func (u *UpdateVulnSeverity) Validate() error {
	return validation.ValidateStruct(u,
		validation.Field(&u.Severity, validation.Required, validation.In(severityEnum.Values()...)),
	)
}

func (u *UpdateVulnSeverity) ToBytes() []byte {
	bytes, _ := json.Marshal(u)
	return bytes
}
