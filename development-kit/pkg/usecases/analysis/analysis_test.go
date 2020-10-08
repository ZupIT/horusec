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

package analysis

import (
	"encoding/json"
	apiEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	horusecEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker/packet"
	"github.com/google/uuid"
	"github.com/streadway/amqp"
	"github.com/stretchr/testify/assert"
)

func TestParsePacketToAnalysisCreate(t *testing.T) {
	t.Run("should success parse packet to analysis", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysisData := &apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{
				ID:        uuid.New(),
				CreatedAt: time.Now(),
			},
			RepositoryName: "",
		}
		bytes, _ := json.Marshal(analysisData)
		p := packet.NewPacket(&amqp.Delivery{})
		p.SetBody(bytes)
		result, err := useCases.ParsePacketToAnalysis(p)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestParsePacketToAnalysisUpdate(t *testing.T) {
	t.Run("should success parse packet to analysis", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{
				ID:        uuid.New(),
				CreatedAt: time.Now(),
			},
			RepositoryName: "",
		}
		p := packet.NewPacket(&amqp.Delivery{})
		p.SetBody(analysis.ToBytes())
		result, err := useCases.ParsePacketToAnalysis(p)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("should return error while unmarshal invalid data", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		p := packet.NewPacket(&amqp.Delivery{})
		p.SetBody(nil)
		_, err := useCases.ParsePacketToAnalysis(p)

		assert.Error(t, err)
	})
}

func TestSetFindOneFilter(t *testing.T) {
	t.Run("should return a map of string and interface", func(t *testing.T) {
		useCases := NewAnalysisUseCases()
		assert.NotEmpty(t, useCases.SetFindOneFilter("test"))
	})
}

func TestDecodeAnalysisFromIoRead(t *testing.T) {
	t.Run("should parse io read to analysis", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysisData := apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{
				Status:     horusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
				AnalysisVulnerabilities: []horusecEntities.AnalysisVulnerabilities{
					{
						Vulnerability: horusecEntities.Vulnerability{
							SecurityTool: tools.GoSec,
							Language:     languages.Go,
							Severity:     severity.NoSec,
							Type:         horusec.Vulnerability,
							VulnHash:     uuid.New().String(),
						},
					},
				},
			},
			RepositoryName: "",
		}
		bytes, _ := json.Marshal(analysisData)

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		result, err := useCases.DecodeAnalysisDataFromIoRead(readCloser)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
	t.Run("should return error parse io read to analysis", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		_, err := useCases.DecodeAnalysisDataFromIoRead(nil)
		assert.Error(t, err)
		assert.Equal(t, EnumErrors.ErrorBodyIsRequired.Error(), err.Error())
	})
	t.Run("should return error while decoding", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		readCloser := ioutil.NopCloser(strings.NewReader("test"))

		_, err := useCases.DecodeAnalysisDataFromIoRead(readCloser)
		assert.Error(t, err)
	})
	t.Run("should return error because multiple field in analysis is wrong", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{},
		}
		bytes, _ := json.Marshal(analysis)
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))
		_, err := useCases.DecodeAnalysisDataFromIoRead(readCloser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "createdAt: cannot be blank")
		assert.Contains(t, err.Error(), "finishedAt: cannot be blank")
		assert.Contains(t, err.Error(), "status: cannot be blank")
	})
	t.Run("should return error because multiple field in vulnerabilities is wrong", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysisData := &apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{
				Status:     horusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
				AnalysisVulnerabilities: []horusecEntities.AnalysisVulnerabilities{
					{
						Vulnerability: horusecEntities.Vulnerability{},
					},
				},
			},
			RepositoryName: "",
		}
		bytes, _ := json.Marshal(analysisData)

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		_, err := useCases.DecodeAnalysisDataFromIoRead(readCloser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "language: cannot be blank")
		assert.Contains(t, err.Error(), "securityTool: cannot be blank")
		assert.Contains(t, err.Error(), "severity: cannot be blank")
	})
	t.Run("should return error because status is wrong", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{
				Status:     "other status",
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
				AnalysisVulnerabilities: []horusecEntities.AnalysisVulnerabilities{
					{
						Vulnerability: horusecEntities.Vulnerability{
							SecurityTool: tools.GoSec,
							Language:     languages.Go,
							Severity:     severity.NoSec,
						},
					},
				},
			},
			RepositoryName: "",
		}
		bytes, _ := json.Marshal(analysis)

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		_, err := useCases.DecodeAnalysisDataFromIoRead(readCloser)
		assert.Error(t, err)
	})
	t.Run("should return error because CreatedAt is wrong", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{
				Status:     horusec.Success,
				CreatedAt:  time.Time{},
				FinishedAt: time.Now(),
				AnalysisVulnerabilities: []horusecEntities.AnalysisVulnerabilities{
					{
						Vulnerability: horusecEntities.Vulnerability{
							SecurityTool: tools.GoSec,
							Language:     languages.Go,
							Severity:     severity.NoSec,
						},
					},
				},
			},
			RepositoryName: "",
		}
		bytes, _ := json.Marshal(analysis)

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		_, err := useCases.DecodeAnalysisDataFromIoRead(readCloser)
		assert.Error(t, err)
	})
	t.Run("should return error because FinishedAt is wrong", func(t *testing.T) {
		useCases := NewAnalysisUseCases()

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusecEntities.Analysis{
				Status:     horusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Time{},
				AnalysisVulnerabilities: []horusecEntities.AnalysisVulnerabilities{
					{
						Vulnerability: horusecEntities.Vulnerability{
							SecurityTool: tools.GoSec,
							Language:     languages.Go,
							Severity:     severity.NoSec,
						},
					},
				},
			},
			RepositoryName: "",
		}
		bytes, _ := json.Marshal(analysis)

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		_, err := useCases.DecodeAnalysisDataFromIoRead(readCloser)
		assert.Error(t, err)
	})
}

func TestNewAnalysisRunning(t *testing.T) {
	t.Run("should return a new analysis", func(t *testing.T) {
		useCases := NewAnalysisUseCases()
		analysis := useCases.NewAnalysisRunning()
		assert.NotEmpty(t, analysis.CreatedAt)
		assert.Equal(t, horusec.Running, analysis.Status)
	})
}
