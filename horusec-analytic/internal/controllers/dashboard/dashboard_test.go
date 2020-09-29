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
	"testing"
	"time"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	dashboardUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/dashboard"
	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	"github.com/stretchr/testify/assert"
)

func queryMock() string {
	return `
		{	
			totalItems(initialDate: "2020-07-19T00:00:00Z", finalDate: "2020-07-21T00:00:00Z")
			analysis(initialDate: "2020-07-19T00:00:00Z", finalDate: "2020-07-21T00:00:00Z"){
				repositoryID
				companyID
			}
		}
	`
}

func TestGetVulnerabilitiesByAuthor(t *testing.T) {
	t.Run("Should return error when executing graphql resolvers", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetDetailsPaginated").Return([]dashboard.VulnDetails{{RepositoryName: "test"}}, nil)
		analysisMock.On("GetDetailsCount").Return(1, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetVulnerabilitiesByAuthor(queryMock(), 1, 15)

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})
}

func TestGetVulnDetailsCount(t *testing.T) {
	t.Run("Should success get vuln total items", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetDetailsPaginated").Return([]dashboard.VulnDetails{{RepositoryName: "test"}}, nil)
		analysisMock.On("GetDetailsCount").Return(1, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		params := &graphql.ResolveParams{
			Args: map[string]interface{}{
				"companyID":   uuid.New().String(),
				"initialDate": time.Now(),
				"finalDate":   time.Now(),
			},
		}

		result, err := controller.getVulnDetailsCount(params)

		assert.NoError(t, err)
		assert.Equal(t, 1, result)
	})
}

func TestGetVulnDetails(t *testing.T) {
	t.Run("Should success get vulnerabilities", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetDetailsPaginated").Return([]dashboard.VulnDetails{{RepositoryName: "test"}}, nil)
		analysisMock.On("GetDetailsCount").Return(1, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		params := &graphql.ResolveParams{
			Args: map[string]interface{}{
				"companyID":   uuid.New().String(),
				"initialDate": time.Now(),
				"finalDate":   time.Now(),
			},
		}

		result, err := controller.getVulnDetails(params, 1, 2)

		assert.NoError(t, err)
		assert.Len(t, result, 1)
	})
}

func TestGetTotalDevelopers(t *testing.T) {
	t.Run("Should success get data with no errors", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetDeveloperCount").Return(3, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetTotalDevelopers(uuid.Nil, uuid.Nil, time.Now(), time.Now())

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Equal(t, 3, result)
	})
}

func TestGetTotalRepositories(t *testing.T) {
	t.Run("Should success get data with no errors", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetRepositoryCount").Return(3, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetTotalRepositories(uuid.Nil, uuid.Nil, time.Now(), time.Now())

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Equal(t, 3, result)
	})
}

func TestGetVulnBySeverity(t *testing.T) {
	t.Run("Should success get data with no errors", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetVulnBySeverity").Return([]dashboard.VulnBySeverity{{Severity: "LOW"}}, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetVulnBySeverity(uuid.Nil, uuid.Nil, time.Now(), time.Now())

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 1)
	})
}

func TestGetVulnByDeveloper(t *testing.T) {
	t.Run("Should success get data with no errors", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetVulnByDeveloper").Return([]dashboard.VulnByDeveloper{{Developer: "test"}}, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetVulnByDeveloper(uuid.Nil, uuid.Nil, time.Now(), time.Now())

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 1)
	})
}

func TestGetVulnByLanguage(t *testing.T) {
	t.Run("Should success get data with no errors", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetVulnByLanguage").Return([]dashboard.VulnByLanguage{{Language: "test"}}, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetVulnByLanguage(uuid.Nil, uuid.Nil, time.Now(), time.Now())

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 1)
	})
}

func TestGetVulnByTime(t *testing.T) {
	t.Run("Should success get data with no errors", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetVulnByTime").Return([]dashboard.VulnByTime{{Time: time.Time{}}}, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetVulnByTime(uuid.Nil, uuid.Nil, time.Now(), time.Now())

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 1)
	})
}

func TestGetVulnByRepository(t *testing.T) {
	t.Run("Should success get data with no errors", func(t *testing.T) {
		analysisMock := &analysis.Mock{}

		analysisMock.On("GetVulnByRepository").Return([]dashboard.VulnByRepository{{Repository: "test"}}, nil)

		controller := Controller{
			useCases:   dashboardUseCases.NewDashboardUseCases(),
			repository: analysisMock,
		}

		result, err := controller.GetVulnByRepository(uuid.Nil, uuid.Nil, time.Now(), time.Now())

		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})
}

func TestNewDashboardController(t *testing.T) {
	t.Run("Should return a new controller", func(t *testing.T) {
		assert.NotEmpty(t, NewDashboardController(nil))
	})
}
