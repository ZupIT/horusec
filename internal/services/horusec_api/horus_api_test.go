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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	enumHorusec "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
)

var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

func createSendHandlerWithStatus(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}
}

func createFindHandlerWithStatus(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Content struct {
			Analysis *analysis.Analysis `json:"content"`
		}

		idSlice := strings.Split(r.URL.Path, "/")
		id := idSlice[3]
		response := Content{
			Analysis: &analysis.Analysis{ID: uuid.MustParse(id)},
		}

		res, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(status)
		w.Write(res)
	}
}

var errorUnmarshallHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
	type Content struct {
		Analysis *analysis.Analysis `json:"invalidName"`
	}

	idSlice := strings.Split(r.URL.Path, "/")
	id := idSlice[3]
	response := Content{
		Analysis: &analysis.Analysis{ID: uuid.MustParse(id)},
	}

	res, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func TestServiceSendAnalysis(t *testing.T) {
	type args struct {
		entity     *analysis.Analysis
		config     *cliConfig.Config
		beforeFunc func() (*httptest.Server, *os.File)
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "should not send analysis when authorization is not set",
			args: args{
				entity: &analysis.Analysis{
					ID:        uuid.New(),
					CreatedAt: time.Now(),
					Status:    enumHorusec.Running,
				},
				config: cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc("/api/analysis", createSendHandlerWithStatus(http.StatusCreated))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, string(localhostCert))
					assert.NoError(t, err)
					return svr, file
				},
			},

			wantErr: false,
		},
		{
			name: "should send analysis with no errors",
			args: args{
				entity: &analysis.Analysis{
					ID:        uuid.New(),
					CreatedAt: time.Now(),
					Status:    enumHorusec.Running,
				},
				config: cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc("/api/analysis", createSendHandlerWithStatus(http.StatusCreated))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, string(localhostCert))
					assert.NoError(t, err)
					return svr, file
				},
			},

			wantErr: false,
		},
		{
			name: "should send analysis with bad request error",
			args: args{
				entity: &analysis.Analysis{
					ID:        uuid.New(),
					CreatedAt: time.Now(),
					Status:    enumHorusec.Running,
				},
				config: cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc("/api/analysis", createSendHandlerWithStatus(http.StatusBadRequest))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, string(localhostCert))
					assert.NoError(t, err)
					return svr, file
				},
			},
			wantErr: true,
		},
		{
			name: "should send analysis with internal server error",
			args: args{
				entity: &analysis.Analysis{
					ID:        uuid.New(),
					CreatedAt: time.Now(),
					Status:    enumHorusec.Running,
				},
				config: cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc("/api/analysis", createSendHandlerWithStatus(http.StatusInternalServerError))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, string(localhostCert))
					assert.NoError(t, err)
					return svr, file
				},
			},
			wantErr: true,
		},
		{
			name: "should send analysis with unauthorized error",
			args: args{
				entity: &analysis.Analysis{
					ID:        uuid.New(),
					CreatedAt: time.Now(),
					Status:    enumHorusec.Running,
				},
				config: cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc("/api/analysis", createSendHandlerWithStatus(http.StatusUnauthorized))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, string(localhostCert))
					assert.NoError(t, err)
					return svr, file
				},
			},
			wantErr: true,
		},
		{
			name: "should get error when parsing invalid certificate",
			args: args{
				entity: &analysis.Analysis{
					ID:        uuid.New(),
					CreatedAt: time.Now(),
					Status:    enumHorusec.Running,
				},
				config: cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc("/api/analysis", createSendHandlerWithStatus(http.StatusCreated))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, "invalidCertificate")
					assert.NoError(t, err)
					return svr, file
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svr, file := tt.args.beforeFunc()
			defer svr.Close()
			tt.args.config.HorusecAPIUri = svr.URL
			tt.args.config.RepositoryAuthorization = "test"
			if tt.name == "should not send analysis when authorization is not set" {
				tt.args.config.RepositoryAuthorization = ""
			}
			tt.args.config.Headers = map[string]string{"some-header": "some-value"}
			tt.args.config.CertPath = file.Name()
			s := NewHorusecAPIService(tt.args.config)
			if err := s.SendAnalysis(tt.args.entity); (err != nil) != tt.wantErr {
				fmt.Println()
				fmt.Printf("ERROR TESTE DE SendAnalysis: %v", err)
				fmt.Println()
				assert.NoError(t, err)
			}
		})
	}
}

func TestServiceGetAnalysis(t *testing.T) {
	expectedUUID := uuid.New()
	type args struct {
		config     *cliConfig.Config
		analysisID uuid.UUID
		beforeFunc func() (*httptest.Server, *os.File)
	}
	tests := []struct {
		name    string
		args    args
		want    uuid.UUID
		wantErr bool
	}{
		{
			name: "Should get analysis without error",
			args: args{
				analysisID: expectedUUID,
				beforeFunc: func() (*httptest.Server, *os.File) {
					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), createFindHandlerWithStatus(http.StatusOK))
					svr := httptest.NewServer(router)
					return svr, nil
				},
				config: cliConfig.New(),
			},
			want:    expectedUUID,
			wantErr: false,
		},
		{
			name: "Should get analysis without error when no authorization is found",
			args: args{
				analysisID: expectedUUID,
				beforeFunc: func() (*httptest.Server, *os.File) {
					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), createFindHandlerWithStatus(http.StatusBadRequest))
					svr := httptest.NewServer(router)
					return svr, nil
				},
				config: cliConfig.New(),
			},
			want:    uuid.MustParse(cliConfig.New().RepositoryAuthorization),
			wantErr: false,
		},
		{
			name: "Should get analysis with error when bad request",
			args: args{
				analysisID: expectedUUID,
				beforeFunc: func() (*httptest.Server, *os.File) {
					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), createFindHandlerWithStatus(http.StatusBadRequest))
					svr := httptest.NewServer(router)
					return svr, nil
				},
				config: cliConfig.New(),
			},
			want:    expectedUUID,
			wantErr: true,
		},
		{
			name: "Should get analysis with error when internal server error",
			args: args{
				analysisID: expectedUUID,
				beforeFunc: func() (*httptest.Server, *os.File) {
					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), createFindHandlerWithStatus(http.StatusInternalServerError))
					svr := httptest.NewServer(router)
					return svr, nil
				},
				config: cliConfig.New(),
			},
			want:    expectedUUID,
			wantErr: true,
		},
		{
			name: "Should get analysis with TLS",
			args: args{
				analysisID: expectedUUID,
				config:     cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), createFindHandlerWithStatus(http.StatusOK))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, string(localhostCert))
					assert.NoError(t, err)
					return svr, file
				},
			},
			want:    expectedUUID,
			wantErr: false,
		},
		{
			name: "Should get error in analysis with TLS when invalid certificate",
			args: args{
				analysisID: expectedUUID,
				config:     cliConfig.New(),
				beforeFunc: func() (*httptest.Server, *os.File) {
					dir := t.TempDir()
					filename := "cert.pem"
					file, err := os.Create(filepath.Join(dir, filename))
					assert.NoError(t, err)
					assert.NotNil(t, file)
					defer file.Close()

					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), createFindHandlerWithStatus(http.StatusOK))
					svr := httptest.NewTLSServer(router)
					_, err = io.WriteString(file, "invalidCertificate")
					assert.NoError(t, err)
					return svr, file
				},
			},
			want:    expectedUUID,
			wantErr: true,
		},
		{
			name: "Should get analysis with error when response body is nil",
			args: args{
				analysisID: expectedUUID,
				beforeFunc: func() (*httptest.Server, *os.File) {
					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), createSendHandlerWithStatus(http.StatusOK))
					svr := httptest.NewServer(router)
					return svr, nil
				},
				config: cliConfig.New(),
			},
			want:    expectedUUID,
			wantErr: true,
		},
		{
			name: "Should get analysis with error when response body is invalid",
			args: args{
				analysisID: expectedUUID,
				beforeFunc: func() (*httptest.Server, *os.File) {
					router := http.NewServeMux()
					router.HandleFunc(fmt.Sprintf("/api/analysis/%s", expectedUUID.String()), errorUnmarshallHandler)
					svr := httptest.NewServer(router)
					return svr, nil
				},
				config: cliConfig.New(),
			},
			want:    expectedUUID,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svr, file := tt.args.beforeFunc()
			defer svr.Close()
			tt.args.config.HorusecAPIUri = svr.URL
			if tt.name != "Should get analysis without error when no authorization is found" {
				tt.args.config.RepositoryAuthorization = "test"
			}
			if file != nil {
				tt.args.config.CertPath = file.Name()
			}
			s := NewHorusecAPIService(tt.args.config)
			gotAnalysis, err := s.GetAnalysis(tt.args.analysisID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if gotAnalysis != nil {
					assert.Equal(t, tt.want.String(), gotAnalysis.ID.String())
				}
			}
		})
	}
}
