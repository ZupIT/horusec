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

package horusecapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/cli"
	"github.com/ZupIT/horusec-devkit/pkg/services/http/request"
	"github.com/ZupIT/horusec-devkit/pkg/services/http/request/entities"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config"
)

type Service struct {
	http   request.IRequest
	config *config.Config
}

func NewHorusecAPIService(cfg *config.Config) *Service {
	return &Service{
		http:   request.NewHTTPRequestService(10), // nolint:gomnd // timeout default already setup
		config: cfg,
	}
}

func (s *Service) SendAnalysis(entity *analysis.Analysis) {
	if s.config.IsEmptyRepositoryAuthorization() || s.config.IsTimeout {
		return
	}

	res, err := s.sendCreateAnalysisRequest(entity)
	if err != nil {
		s.loggerSendError(err)
		return
	}
	defer res.CloseBody()

	s.loggerSendError(s.verifyResponseCreateAnalysis(res))
}

func (s *Service) GetAnalysis(analysisID uuid.UUID) *analysis.Analysis {
	if s.config.IsEmptyRepositoryAuthorization() || s.config.IsTimeout {
		return nil
	}

	res, err := s.sendFindAnalysisRequest(analysisID)
	if err != nil {
		s.loggerSendError(err)
		return nil
	}
	defer res.CloseBody()
	body, err := s.verifyResponseFindAnalysis(res)
	s.loggerSendError(err)
	return body
}

func (s *Service) sendFindAnalysisRequest(analysisID uuid.UUID) (*entities.HTTPResponse, error) {
	url := s.getHorusecAPIURL() + "/" + analysisID.String()
	req, err := s.http.NewHTTPRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := s.setTLSConfig()
	if err != nil {
		return nil, err
	}

	s.addHeaders(req)
	return s.http.DoRequest(req, tlsConfig)
}

func (s *Service) sendCreateAnalysisRequest(entity *analysis.Analysis) (*entities.HTTPResponse, error) {
	url := s.getHorusecAPIURL()
	body := s.newRequestData(entity)
	req, err := s.http.NewHTTPRequest(http.MethodPost, url, body, nil)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := s.setTLSConfig()
	if err != nil {
		return nil, err
	}

	s.addHeaders(req)
	return s.http.DoRequest(req, tlsConfig)
}

func (s *Service) verifyResponseCreateAnalysis(response *entities.HTTPResponse) error {
	if response.GetStatusCode() == http.StatusCreated {
		return nil
	}

	body, err := response.GetBodyBytes()
	if err != nil {
		return err
	}
	if response.GetStatusCode() == http.StatusBadRequest {
		return fmt.Errorf("something went wrong while sending analysis to horusec. " +
			"Check if your current version of Horusec-CLI is compatible with version in Horusec-API -> " +
			string(body))
	}
	return fmt.Errorf("something went wrong while sending analysis to horusec -> %s", string(body))
}

func (s *Service) verifyResponseFindAnalysis(response *entities.HTTPResponse) (entity *analysis.Analysis, err error) {
	body, err := response.GetBodyBytes()
	if err != nil {
		return nil, err
	}
	if response.ErrorByStatusCode() != nil {
		return nil, fmt.Errorf("something went wrong while finding analysis to horusec -> %s", string(body))
	}
	return s.parseResponseBytesToAnalysis(body)
}

func (s *Service) parseResponseBytesToAnalysis(body []byte) (entity *analysis.Analysis, err error) {
	var res map[string]interface{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	body, err = json.Marshal(res["content"])
	if err != nil {
		return nil, err
	}
	return entity, json.Unmarshal(body, &entity)
}

func (s *Service) getHorusecAPIURL() string {
	return fmt.Sprintf("%s/api/analysis", s.config.HorusecAPIUri)
}

func (s *Service) loggerSendError(err error) {
	if err != nil {
		print("\n")
		logger.LogStringAsError(fmt.Sprintf("[HORUSEC] %s", err.Error()))
	}
}

func (s *Service) setTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.config.CertInsecureSkipVerify, // nolint:gosec // skip dynamic
	}
	if s.config.CertPath != "" {
		caCert, err := ioutil.ReadFile(s.config.CertPath)
		if err != nil {
			return tlsConfig, err
		}

		certPool := x509.NewCertPool()
		_ = certPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = certPool
	}

	return tlsConfig, nil
}

func (s *Service) newRequestData(entity *analysis.Analysis) *cli.AnalysisData {
	return &cli.AnalysisData{
		Analysis:       entity,
		RepositoryName: s.config.RepositoryName,
	}
}

func (s *Service) addHeaders(req *http.Request) {
	if req.Header == nil {
		req.Header = http.Header{}
	}
	req.Header.Add("X-Horusec-CLI-Version", s.config.Version)
	req.Header.Add("X-Horusec-Authorization", s.config.RepositoryAuthorization)
	for key, value := range s.config.Headers {
		req.Header.Add(key, value)
	}
}
