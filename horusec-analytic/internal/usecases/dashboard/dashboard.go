// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dashboard

import (
	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	"time"
)

type IUseCases interface {
	CreateQueryTypeArgs() graphql.FieldConfigArgument
	VulnDetailsGraphqlObject() *graphql.Object
	GetCompanyIDByParams(params *graphql.ResolveParams) (companyID uuid.UUID)
	GetRepositoryIDByParams(params *graphql.ResolveParams) uuid.UUID
	GetInitialDateByParams(params *graphql.ResolveParams) time.Time
	GetFinalDateByParams(params *graphql.ResolveParams) time.Time
}

type UseCases struct {
}

func NewDashboardUseCases() IUseCases {
	return &UseCases{}
}

func (u *UseCases) GetCompanyIDByParams(params *graphql.ResolveParams) (companyID uuid.UUID) {
	if id := params.Args["companyID"]; id != nil {
		companyID, _ = uuid.Parse(id.(string))
	}

	return companyID
}

func (u *UseCases) GetRepositoryIDByParams(params *graphql.ResolveParams) (repositoryID uuid.UUID) {
	if id := params.Args["repositoryID"]; id != nil {
		repositoryID, _ = uuid.Parse(id.(string))
	}

	return repositoryID
}

func (u *UseCases) GetInitialDateByParams(params *graphql.ResolveParams) time.Time {
	initialDate, _ := params.Args["initialDate"].(time.Time)
	return initialDate
}

func (u *UseCases) GetFinalDateByParams(params *graphql.ResolveParams) time.Time {
	finalDate, _ := params.Args["finalDate"].(time.Time)
	return finalDate
}

func (u *UseCases) CreateQueryTypeArgs() graphql.FieldConfigArgument {
	return graphql.FieldConfigArgument{
		"companyID": &graphql.ArgumentConfig{
			Type: graphql.ID,
		},
		"repositoryID": &graphql.ArgumentConfig{
			Type: graphql.ID,
		},
		"initialDate": &graphql.ArgumentConfig{
			Type: graphql.DateTime,
		},
		"finalDate": &graphql.ArgumentConfig{
			Type: graphql.DateTime,
		},
	}
}

func (u *UseCases) VulnDetailsGraphqlObject() *graphql.Object {
	return createAnalysisType()
}
