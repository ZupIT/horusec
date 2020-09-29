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
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	analysisRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/analysis"
	dashboardEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	dashboardUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/dashboard"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
)

type IController interface {
	GetVulnerabilitiesByAuthor(query string, page, size int) (*graphql.Result, error)
	GetTotalDevelopers(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (int, error)
	GetTotalRepositories(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (int, error)
	GetVulnBySeverity(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) ([]dashboardEntities.VulnBySeverity, error)
	GetVulnByDeveloper(companyID, repositoryID uuid.UUID,
		initialDate, finalDate time.Time) ([]dashboardEntities.VulnByDeveloper, error)
	GetVulnByLanguage(companyID, repositoryID uuid.UUID,
		initialDate, finalDate time.Time) ([]dashboardEntities.VulnByLanguage, error)
	GetVulnByTime(companyID, repositoryID uuid.UUID,
		initialDate, finalDate time.Time) ([]dashboardEntities.VulnByTime, error)
	GetVulnByRepository(companyID, repositoryID uuid.UUID,
		initialDate, finalDate time.Time) ([]dashboardEntities.VulnByRepository, error)
}

type Controller struct {
	useCases   dashboardUseCases.IUseCases
	repository analysisRepository.IAnalysisRepository
}

func NewDashboardController(postgresRead relational.InterfaceRead) IController {
	return &Controller{
		useCases:   dashboardUseCases.NewDashboardUseCases(),
		repository: analysisRepository.NewAnalysisRepository(postgresRead, nil),
	}
}

func (c *Controller) GetVulnerabilitiesByAuthor(query string, page, size int) (*graphql.Result, error) {
	schema, err := graphql.NewSchema(graphql.SchemaConfig{Query: graphql.NewObject(c.createQueryType(page, size))})
	logger.LogError(errors.ErrorGraphqlSchema, err)
	return graphql.Do(graphql.Params{Schema: schema, RequestString: query}), err
}

func (c *Controller) createQueryType(page, size int) graphql.ObjectConfig {
	return graphql.ObjectConfig{Name: "QueryType", Fields: graphql.Fields{
		"analysis": &graphql.Field{
			Type: graphql.NewList(c.useCases.VulnDetailsGraphqlObject()),
			Args: c.useCases.CreateQueryTypeArgs(),
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				return c.getVulnDetails(&params, page, size)
			}},
		"totalItems": &graphql.Field{
			Type: graphql.Int,
			Args: c.useCases.CreateQueryTypeArgs(),
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				return c.getVulnDetailsCount(&params)
			}},
	}}
}

func (c *Controller) getVulnDetails(params *graphql.ResolveParams,
	page, size int) ([]dashboardEntities.VulnDetails, error) {
	result, err := c.repository.GetDetailsPaginated(c.useCases.GetCompanyIDByParams(params),
		c.useCases.GetRepositoryIDByParams(params), page, size, c.useCases.GetInitialDateByParams(params),
		c.useCases.GetFinalDateByParams(params))

	logger.LogError("{GetVulnDetails} something went wrong ->", err)

	return result, err
}

func (c *Controller) getVulnDetailsCount(params *graphql.ResolveParams) (int, error) {
	result, err := c.repository.GetDetailsCount(c.useCases.GetCompanyIDByParams(params),
		c.useCases.GetRepositoryIDByParams(params), c.useCases.GetInitialDateByParams(params),
		c.useCases.GetFinalDateByParams(params))

	logger.LogError("{GetVulnDetailsCount} something went wrong ->", err)

	return result, err
}

func (c *Controller) GetTotalDevelopers(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (int, error) {
	result, err := c.repository.GetDeveloperCount(companyID, repositoryID, initialDate, finalDate)

	logger.LogError("{GetTotalDevelopers} something went wrong ->", err)

	return result, err
}

func (c *Controller) GetTotalRepositories(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (int, error) {
	result, err := c.repository.GetRepositoryCount(companyID, repositoryID, initialDate, finalDate)

	logger.LogError("{GetTotalRepositories} something went wrong ->", err)

	return result, err
}

func (c *Controller) GetVulnBySeverity(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) ([]dashboardEntities.VulnBySeverity, error) {
	result, err := c.repository.GetVulnBySeverity(companyID, repositoryID, initialDate, finalDate)

	logger.LogError("{GetVulnBySeverity} something went wrong ->", err)

	return result, err
}

func (c *Controller) GetVulnByDeveloper(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByDeveloper, error) {
	result, err := c.repository.GetVulnByDeveloper(companyID, repositoryID, initialDate, finalDate)

	logger.LogError("{GetVulnByDeveloper} something went wrong ->", err)

	return result, err
}

func (c *Controller) GetVulnByLanguage(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByLanguage, error) {
	result, err := c.repository.GetVulnByLanguage(companyID, repositoryID, initialDate, finalDate)

	logger.LogError("{GetVulnByLanguage} something went wrong ->", err)

	return result, err
}

func (c *Controller) GetVulnByTime(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByTime, error) {
	result, err := c.repository.GetVulnByTime(companyID, repositoryID, initialDate, finalDate)

	logger.LogError("{GetVulnByTime} something went wrong ->", err)

	return result, err
}

func (c *Controller) GetVulnByRepository(companyID, repositoryID uuid.UUID,
	initialDate, finalDate time.Time) ([]dashboardEntities.VulnByRepository, error) {
	result, err := c.repository.GetVulnByRepository(companyID, repositoryID, initialDate, finalDate)

	logger.LogError("{GetVulnByRepository} something went wrong ->", err)

	return result, err
}
