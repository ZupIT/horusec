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
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGetCompanyIDByParams(t *testing.T) {
	t.Run("should get company id and parse", func(t *testing.T) {

		useCases := NewDashboardUseCases()

		id := uuid.New()

		params := &graphql.ResolveParams{
			Args: map[string]interface{}{
				"companyID": id.String(),
			},
		}

		companyID := useCases.GetCompanyIDByParams(params)
		assert.Equal(t, id, companyID)
	})

	t.Run("should return a empty uuid", func(t *testing.T) {
		useCases := NewDashboardUseCases()

		params := &graphql.ResolveParams{}

		companyID := useCases.GetCompanyIDByParams(params)
		assert.Equal(t, uuid.Nil, companyID)
	})
}

func TestGetRepositoryIDByParams(t *testing.T) {
	t.Run("should get repository id and parse", func(t *testing.T) {

		useCases := NewDashboardUseCases()

		id := uuid.New()

		params := &graphql.ResolveParams{
			Args: map[string]interface{}{
				"repositoryID": id.String(),
			},
		}

		repositoryID := useCases.GetRepositoryIDByParams(params)
		assert.Equal(t, id, repositoryID)
	})

	t.Run("should return a empty uuid", func(t *testing.T) {
		useCases := NewDashboardUseCases()

		params := &graphql.ResolveParams{}

		repositoryID := useCases.GetRepositoryIDByParams(params)
		assert.Equal(t, uuid.Nil, repositoryID)
	})
}

func TestGetInitialDateByParams(t *testing.T) {
	t.Run("should get date by params", func(t *testing.T) {

		useCases := NewDashboardUseCases()

		id := uuid.New()

		params := &graphql.ResolveParams{
			Args: map[string]interface{}{
				"initialDate": time.Now(),
			},
		}

		date := useCases.GetInitialDateByParams(params)
		assert.NotEmpty(t, id, date)
	})
}

func TestGetFinalDateByParams(t *testing.T) {
	t.Run("should get date by params", func(t *testing.T) {

		useCases := NewDashboardUseCases()

		id := uuid.New()

		params := &graphql.ResolveParams{
			Args: map[string]interface{}{
				"finalDate": time.Now(),
			},
		}

		date := useCases.GetFinalDateByParams(params)
		assert.NotEmpty(t, id, date)
	})
}

//func TestParseResponseToVulnDetails(t *testing.T) {
//	t.Run("should success parse response to vulnerabilities", func(t *testing.T) {
//		useCases := NewDashboardUseCases()
//
//		id := uuid.New()
//
//		data := []bson.M{
//			{"companyName": "test"},
//		}
//
//		resp := &response.Response{}
//		resp.SetData(data)
//
//		result := useCases.ParseResponseToVulnDetails(resp)
//		assert.NotEmpty(t, id, result)
//		assert.Len(t, result, 1)
//	})
//}

func TestCreateQueryTypeArgs(t *testing.T) {
	t.Run("should success create  graphql args", func(t *testing.T) {
		useCases := NewDashboardUseCases()

		result := useCases.CreateQueryTypeArgs()
		assert.NotEmpty(t, result)
	})
}

func TestVulnDetailsGraphqlObject(t *testing.T) {
	t.Run("should success create  graphql object", func(t *testing.T) {
		useCases := NewDashboardUseCases()

		result := useCases.VulnDetailsGraphqlObject()
		assert.NotEmpty(t, result)
	})
}
