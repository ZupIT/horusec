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

package horusapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"io/ioutil"
	"net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
)

type IService interface {
	SendAnalysis(analysis *horusec.Analysis)
}

type Service struct {
	httpUtil client.Interface
	config   *cliConfig.Config
}

func NewHorusecAPIService(config *cliConfig.Config) IService {
	return &Service{
		httpUtil: client.NewHTTPClient(10),
		config:   config,
	}
}

func (s *Service) SendAnalysis(analysis *horusec.Analysis) {
	if s.config.IsEmptyRepositoryAuthorization() || s.config.IsTimeout {
		return
	}

	response, err := s.sendRequest(analysis)
	if err != nil {
		s.loggerSendError(err)
		return
	}

	s.loggerSendError(s.verifyResponse(response))
}

func (s *Service) sendRequest(analysis *horusec.Analysis) (httpResponse.Interface, error) {
	req, err := http.NewRequest(http.MethodPost, s.getHorusecAPIURL(), bytes.NewReader(s.newRequestData(analysis)))
	if err != nil {
		return nil, err
	}

	tlsConfig, err := s.setTLSConfig()
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", s.config.GetRepositoryAuthorization())
	return s.httpUtil.DoRequest(req, tlsConfig)
}

func (s *Service) verifyResponse(response httpResponse.Interface) error {
	if response.GetStatusCode() == 201 {
		return nil
	}

	body, err := response.GetBody()
	if err != nil {
		return err
	}

	return fmt.Errorf("something went wrong while sending analysis to horusec -> %s", string(body))
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
	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = s.config.CertInsecureSkipVerify

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

func (s *Service) newRequestData(analysis *horusec.Analysis) []byte {
	analysisData := &api.AnalysisData{
		Analysis:       analysis,
		RepositoryName: s.config.RepositoryName,
	}

	return analysisData.ToBytes()
}
