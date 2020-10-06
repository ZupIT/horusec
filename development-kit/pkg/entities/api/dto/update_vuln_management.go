package dto

import (
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type UpdateManagementData struct {
	Status horusecEnums.AnalysisVulnerabilitiesStatus `json:"status"`
	Type   horusecEnums.AnalysisVulnerabilitiesType   `json:"type"`
}

func (u *UpdateManagementData) Validate() error {
	return validation.ValidateStruct(u,
		validation.Field(&u.Status, validation.In(u.StatusValues()...)),
		validation.Field(&u.Type, validation.In(u.TypeValues()...)),
	)
}

func (u UpdateManagementData) StatusValues() []interface{} {
	return []interface{}{
		horusecEnums.Approved,
		horusecEnums.Reproved,
		horusecEnums.NoAction,
		"",
	}
}

func (u UpdateManagementData) TypeValues() []interface{} {
	return []interface{}{
		horusecEnums.FalsePositive,
		horusecEnums.RiskAccepted,
		horusecEnums.Vulnerability,
		"",
	}
}
