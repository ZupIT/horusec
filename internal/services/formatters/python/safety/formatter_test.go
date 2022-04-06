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

package safety

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	enumHorusec "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/copy"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func getAnalysis() *entitiesAnalysis.Analysis {
	return &entitiesAnalysis.Analysis{
		ID:                      uuid.New(),
		RepositoryID:            uuid.New(),
		WorkspaceID:             uuid.New(),
		Status:                  enumHorusec.Running,
		Errors:                  "",
		CreatedAt:               time.Now(),
		AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{},
	}
}

func TestNewFormatter(t *testing.T) {
	config := &cliConfig.Config{}
	config.WorkDir = &workdir.WorkDir{}

	service := formatters.NewFormatterService(nil, nil, config)

	assert.IsType(t, NewFormatter(service), &Formatter{})
}

func TestFormatter_StartSafety(t *testing.T) {
	t.Run("Should return error when start analysis", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("Error"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("Should execute analysis without error", func(t *testing.T) {
		analysis := getAnalysis()

		config := cliConfig.New()
		config.ProjectPath = t.TempDir()
		srcProject := testutil.PythonExample
		dstProject := filepath.Join(config.ProjectPath, ".horusec", analysis.ID.String())
		assert.NoError(t, copy.Copy(srcProject, dstProject, func(src string) bool {
			return false
		}))
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Equal(t, 23, len(analysis.AnalysisVulnerabilities))

		for _, av := range analysis.AnalysisVulnerabilities {
			vuln := av.Vulnerability
			assert.Equal(t, tools.Safety, vuln.SecurityTool)
			assert.Equal(t, languages.Python, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")
		}

		t.Cleanup(func() {
			err := os.RemoveAll(t.TempDir())
			assert.NoError(t, err, "Expected nil error to clean up: %v", err)
		})
	})

	t.Run("Should return nil when output is empty analysis", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("Should return nil when output is wrong format analysis", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("some aleatory text", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := testutil.NewDockerMock()
		config := &cliConfig.Config{}
		config.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Safety: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

const output = `
{
    "issues":[
        {
            "dependency":"django",
            "vulnerable_below":"<1.11.27",
            "installed_version":"1.3.10",
            "description":"Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.) See CVE-2019-19844.",
            "id":"37771"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.4.14",
            "installed_version":"1.3.10",
            "description":"The administrative interface (contrib.admin) in Django before 1.4.14, 1.5.x before 1.5.9, 1.6.x before 1.6.6, and 1.7 before release candidate 3 does not check if a field represents a relationship between models, which allows remote authenticated users to obtain sensitive information via a to_field parameter in a popup action to an admin change form page, as demonstrated by a /admin/auth/user/?pop=1&t=password URI. See: CVE-2014-0483.",
            "id":"35516"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.4.18",
            "installed_version":"1.3.10",
            "description":"The django.views.static.serve view in Django before 1.4.18, 1.6.x before 1.6.10, and 1.7.x before 1.7.3 reads files an entire line at a time, which allows remote attackers to cause a denial of service (memory consumption) via a long line in a file.",
            "id":"33072"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.4.18",
            "installed_version":"1.3.10",
            "description":"The django.util.http.is_safe_url function in Django before 1.4.18, 1.6.x before 1.6.10, and 1.7.x before 1.7.3 does not properly handle leading whitespaces, which allows remote attackers to conduct cross-site scripting (XSS) attacks via a crafted URL, related to redirect URLs, as demonstrated by a \"\\njavascript:\" URL.",
            "id":"33071"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.4.18",
            "installed_version":"1.3.10",
            "description":"Django before 1.4.18, 1.6.x before 1.6.10, and 1.7.x before 1.7.3 allows remote attackers to spoof WSGI headers by using an _ (underscore) character instead of a - (dash) character in an HTTP header, as demonstrated by an X-Auth_User header.",
            "id":"33070"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.4.20",
            "installed_version":"1.3.10",
            "description":"The utils.http.is_safe_url function in Django before 1.4.20, 1.5.x, 1.6.x before 1.6.11, 1.7.x before 1.7.7, and 1.8.x before 1.8c1 does not properly validate URLs, which allows remote attackers to conduct cross-site scripting (XSS) attacks via a control character in a URL, as demonstrated by a \\x08javascript: URL.",
            "id":"25713"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.7.11",
            "installed_version":"1.3.10",
            "description":"The get_format function in utils/formats.py in Django before 1.7.x before 1.7.11, 1.8.x before 1.8.7, and 1.9.x before 1.9rc2 might allow remote attackers to obtain sensitive application secrets via a settings key in place of a date/time format setting, as demonstrated by SECRET_KEY.",
            "id":"25714"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.7.6",
            "installed_version":"1.3.10",
            "description":"Cross-site scripting (XSS) vulnerability in the contents function in admin/helpers.py in Django before 1.7.6 and 1.8 before 1.8b2 allows remote attackers to inject arbitrary web script or HTML via a model attribute in ModelAdmin.readonly_fields, as demonstrated by a @property.",
            "id":"25715"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.8.10",
            "installed_version":"1.3.10",
            "description":"The utils.http.is_safe_url function in Django before 1.8.10 and 1.9.x before 1.9.3 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks or possibly conduct cross-site scripting (XSS) attacks via a URL containing basic authentication, as demonstrated by http://mysite.example.com\\@attacker.com.",
            "id":"33073"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.8.10",
            "installed_version":"1.3.10",
            "description":"The password hasher in contrib/auth/hashers.py in Django before 1.8.10 and 1.9.x before 1.9.3 allows remote attackers to enumerate users via a timing attack involving login requests.",
            "id":"33074"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<1.8.15",
            "installed_version":"1.3.10",
            "description":"The cookie parsing code in Django before 1.8.15 and 1.9.x before 1.9.10, when used on a site with Google Analytics, allows remote attackers to bypass an intended CSRF protection mechanism by setting arbitrary cookies.",
            "id":"25718"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<2.2.24",
            "installed_version":"1.3.10",
            "description":"Django before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4 has a potential directory traversal via django.contrib.admindocs. Staff members could use the TemplateDetailView view to check the existence of arbitrary files. Additionally, if (and only if) the default admindocs templates have been customized by application developers to also show file contents, then not only the existence but also the file contents would have been exposed. In other words, there is directory traversal outside of the template root directories.",
            "id":"40637"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<2.2.25",
            "installed_version":"1.3.10",
            "description":"Django versions 2.2.25, 3.1.14 and 3.2.10 include a fix for CVE-2021-44420: In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with trailing newlines could bypass upstream access control based on URL paths.\r\nhttps://www.djangoproject.com/weblog/2021/dec/07/security-releases/",
            "id":"43041"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<2.2.26",
            "installed_version":"1.3.10",
            "description":"Django 2.2.26, 3.2.11 and 4.0.1 include a fix for CVE-2021-45116: An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. Due to leveraging the Django Template Language's variable resolution logic, the dictsort template filter was potentially vulnerable to information disclosure, or an unintended method call, if passed a suitably crafted key.\r\nhttps://www.djangoproject.com/weblog/2022/jan/04/security-releases/",
            "id":"44427"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<2.2.26",
            "installed_version":"1.3.10",
            "description":"Django 2.2.26, 3.2.11 and 4.0.1 include a fix for CVE-2021-45452: Storage.save in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1 allows directory traversal if crafted filenames are directly passed to it.\r\nhttps://www.djangoproject.com/weblog/2022/jan/04/security-releases/",
            "id":"44426"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<2.2.26",
            "installed_version":"1.3.10",
            "description":"Django 2.2.26, 3.2.11 and 4.0.1 include a fix for CVE-2021-45115: An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. UserAttributeSimilarityValidator incurred significant overhead in evaluating a submitted password that was artificially large in relation to the comparison values. In a situation where access to user registration was unrestricted, this provided a potential vector for a denial-of-service attack.\r\nhttps://www.djangoproject.com/weblog/2022/jan/04/security-releases/",
            "id":"44423"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<2.2.27",
            "installed_version":"1.3.10",
            "description":"An issue was discovered in MultiPartParser in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2. Passing certain inputs to multipart forms could result in an infinite loop when parsing files.",
            "id":"44741"
        },
        {
            "dependency":"django",
            "vulnerable_below":"<2.2.27",
            "installed_version":"1.3.10",
            "description":"The {% debug %} template tag in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2 does not properly encode the current context. This may lead to XSS.",
            "id":"44742"
        },
        {
            "dependency":"flask",
            "vulnerable_below":"<0.12.3",
            "installed_version":"0.5.1",
            "description":"flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3.",
            "id":"36388"
        },
        {
            "dependency":"flask",
            "vulnerable_below":"<0.12.3",
            "installed_version":"0.5.1",
            "description":"Flask 0.12.3 includes a fix for CVE-2019-1010083: Unexpected memory usage. The impact is denial of service. The attack vector is crafted encoded JSON data. NOTE: this may overlap CVE-2018-1000656.\r\nhttps://github.com/pallets/flask/pull/2695/commits/0e1e9a04aaf29ab78f721cfc79ac2a691f6e3929",
            "id":"38654"
        },
        {
            "dependency":"flask",
            "vulnerable_below":"<0.6.1",
            "installed_version":"0.5.1",
            "description":"flask 0.6.1 fixes a security problem that allowed clients to download arbitrary files  if the host server was a windows based operating system and the client  uses backslashes to escape the directory the files where exposed from.",
            "id":"25820"
        },
        {
            "dependency":"jinja2",
            "vulnerable_below":"<2.11.3",
            "installed_version":"2.7.2",
            "description":"This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDoS vulnerability is mainly due to the '_punctuation_re regex' operator and its use of multiple wildcards. The last wildcard is the most exploitable as it searches for trailing punctuation. This issue can be mitigated by Markdown to format user content instead of the urlize filter, or by implementing request timeouts and limiting process memory. See: CVE-2020-28493.",
            "id":"39525"
        },
        {
            "dependency":"jinja2",
            "vulnerable_below":"<2.7.3",
            "installed_version":"2.7.2",
            "description":"The default configuration for bccache.FileSystemBytecodeCache in Jinja2 before 2.7.2 does not properly create temporary files, which allows local users to gain privileges via a crafted .cache file with a name starting with __jinja2_ in /tmp.",
            "id":"25866"
        }
    ]
}
`
