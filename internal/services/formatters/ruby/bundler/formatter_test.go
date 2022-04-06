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

package bundler

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestParseOutput(t *testing.T) {
	t.Run("should add 39 vulnerabilities on analysis with no errors", func(t *testing.T) {
		newAnalysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, newTestConfig(t, newAnalysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, newAnalysis.AnalysisVulnerabilities, 39)
		for _, v := range newAnalysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability
			assert.Equal(t, tools.BundlerAudit, vuln.SecurityTool)
			assert.Equal(t, languages.Ruby, vuln.Language)
			assert.Equal(t, confidence.Medium, vuln.Confidence)
			assert.NotEmpty(t, vuln.Details, "Exepcted not empty details")
			assert.NotEmpty(t, vuln.Details, "")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")
		}
	})

	t.Run("should add error and no vulnerabilities on analysis when parse invalid output", func(t *testing.T) {
		newAnalysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, newTestConfig(t, newAnalysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, newAnalysis.HasErrors(), "Expected no errors on analysis")
		assert.Len(t, newAnalysis.AnalysisVulnerabilities, 0)
	})

	t.Run("should add error of the cannot connect in db", func(t *testing.T) {
		newAnalysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("fatal: unable to access 'https://github.com/rubysec/ruby-advisory-db.git/': Could not resolve host: github.com", nil)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, newTestConfig(t, newAnalysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
		assert.Contains(t, newAnalysis.Errors, messages.MsgErrorBundlerNotAccessDB)
		assert.Len(t, newAnalysis.AnalysisVulnerabilities, 0)
	})

	t.Run("should not return any vulnerability if output is empty", func(t *testing.T) {
		newAnalysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, newTestConfig(t, newAnalysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Contains(t, newAnalysis.Errors, ErrGemLockNotFound.Error())
		assert.Len(t, newAnalysis.AnalysisVulnerabilities, 0)
	})

	t.Run("Should add error on analysis when something went wrong in container", func(t *testing.T) {
		newAnalysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, newTestConfig(t, newAnalysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, newAnalysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		newAnalysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.BundlerAudit: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
	})
}

func newTestConfig(t *testing.T, newAnalysis *analysis.Analysis) *config.Config {
	cfg := config.New()
	cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, newAnalysis, testutil.RubyExample1)
	return cfg
}

// output contains the expected output from bundler
//
// Note, output from bundler is colored, and the formatter remove this colors
// before the parsing, so the expected output.
//
// This output has the following schema:
//
// Name: actionpack
// Version: 6.0.0
// Advisory: CVE-2020-8164
// Criticality: Unknown
// URL: https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY
// Title: Possible Strong Parameters Bypass in ActionPack
// Solution: upgrade to ~> 5.2.4.3, >= 6.0.3.1
//
const output = `
{
  "version": "0.9.0.1",
  "created_at": "2022-03-25 17:14:14 +0000",
  "results": [
    {
      "type": "unpatched_gem",
      "gem": {
        "name": "actionpack",
        "version": "6.0.0"
      },
      "advisory": {
        "path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2020-8164.yml",
        "id": "CVE-2020-8164",
        "url": "https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY",
        "title": "Possible Strong Parameters Bypass in ActionPack",
        "date": "2020-05-18",
        "description": "There is a strong parameters bypass vector in ActionPack.\n\nVersions Affected:  rails <= 6.0.3\nNot affected:       rails < 4.0.0\nFixed Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1\n\nImpact\n------\nIn some cases user supplied information can be inadvertently leaked from\nStrong Parameters.  Specifically the return value of 'each', or 'each_value',\nor 'each_pair' will return the underlying \"untrusted\" hash of data that was\nread from the parameters.  Applications that use this return value may be\ninadvertently use untrusted user input.\n\nImpacted code will look something like this:\n\n'\ndef update\n  # Attacker has included the parameter: '{ is_admin: true }'\n  User.update(clean_up_params)\nend\n\ndef clean_up_params\n   params.each { |k, v|  SomeModel.check(v) if k == :name }\nend\n'\n\nNote the mistaken use of 'each' in the 'clean_up_params' method in the above\nexample.\n\nWorkarounds\n-----------\nDo not use the return values of 'each', 'each_value', or 'each_pair' in your\napplication.\n",
        "cvss_v2": null,
        "cvss_v3": null,
        "cve": "2020-8164",
        "osvdb": null,
        "ghsa": "8727-m6gj-mc37",
        "unaffected_versions": [
          "< 4.0.0"
        ],
        "patched_versions": [
          "~> 5.2.4, >= 5.2.4.3",
          ">= 6.0.3.1"
        ],
        "criticality": null
      }
    },
    {
      "type": "unpatched_gem",
      "gem": {
        "name": "actionpack",
        "version": "6.0.0"
      },
      "advisory": {
        "path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2020-8166.yml",
        "id": "CVE-2020-8166",
        "url": "https://groups.google.com/forum/#!topic/rubyonrails-security/NOjKiGeXUgw",
        "title": "Ability to forge per-form CSRF tokens given a global CSRF token",
        "date": "2020-05-18",
        "description": "It is possible to possible to, given a global CSRF token such as the one\npresent in the authenticity_token meta tag, forge a per-form CSRF token for\nany action for that session.\n\nVersions Affected:  rails < 5.2.5, rails < 6.0.4\nNot affected:       Applications without existing HTML injection vulnerabilities.\nFixed Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1\n\nImpact\n------\n\nGiven the ability to extract the global CSRF token, an attacker would be able to\nconstruct a per-form CSRF token for that session.\n\nWorkarounds\n-----------\n\nThis is a low-severity security issue. As such, no workaround is necessarily\nuntil such time as the application can be upgraded.\n",
        "cvss_v2": null,
        "cvss_v3": 4.3,
        "cve": "2020-8166",
        "osvdb": null,
        "ghsa": "jp5v-5gx4-jmj9",
        "unaffected_versions": [

        ],
        "patched_versions": [
          "~> 5.2.4, >= 5.2.4.3",
          ">= 6.0.3.1"
        ],
        "criticality": "medium"
      }
    },
    {
      "type": "unpatched_gem",
      "gem": {
        "name": "actionpack",
        "version": "6.0.0"
      },
      "advisory": {
        "path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2020-8185.yml",
        "id": "CVE-2020-8185",
        "url": "https://groups.google.com/g/rubyonrails-security/c/pAe9EV8gbM0",
        "title": "Untrusted users able to run pending migrations in production",
        "date": "2020-06-17",
        "description": "There is a vulnerability in versions of Rails prior to 6.0.3.2 that allowed\nan untrusted user to run any pending migrations on a Rails app running in\nproduction.\n\nThis vulnerability has been assigned the CVE identifier CVE-2020-8185.\n\nVersions Affected:  6.0.0 < rails < 6.0.3.2\nNot affected:       Applications with 'config.action_dispatch.show_exceptions = false' (this is not a default setting in production)\nFixed Versions:     rails >= 6.0.3.2\n\nImpact\n------\n\nUsing this issue, an attacker would be able to execute any migrations that\nare pending for a Rails app running in production mode. It is important to\nnote that an attacker is limited to running migrations the application\ndeveloper has already defined in their application and ones that have not\nalready ran.\n\nWorkarounds\n-----------\n\nUntil such time as the patch can be applied, application developers should\ndisable the ActionDispatch middleware in their production environment via\na line such as this one in their config/environment/production.rb:\n\n'config.middleware.delete ActionDispatch::ActionableExceptions'\n",
        "cvss_v2": null,
        "cvss_v3": 6.5,
        "cve": "2020-8185",
        "osvdb": null,
        "ghsa": "c6qr-h5vq-59jc",
        "unaffected_versions": [
          "< 6.0.0"
        ],
        "patched_versions": [
          ">= 6.0.3.2"
        ],
        "criticality": "medium"
      }
    },
    {
      "type": "unpatched_gem",
      "gem": {
        "name": "actionpack",
        "version": "6.0.0"
      },
      "advisory": {
        "path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2020-8264.yml",
        "id": "CVE-2020-8264",
        "url": "https://groups.google.com/g/rubyonrails-security/c/yQzUVfv42jk",
        "title": "Possible XSS Vulnerability in Action Pack in Development Mode",
        "date": "2020-10-07",
        "description": "There is a possible XSS vulnerability in Action Pack while the application\nserver is in development mode.  This vulnerability is in the Actionable\nExceptions middleware.  This vulnerability has been assigned the CVE\nidentifier CVE-2020-8264.\n\nVersions Affected:  >= 6.0.0\nNot affected:       < 6.0.0\nFixed Versions:     6.0.3.4\n\nImpact\n------\nWhen an application is running in development mode, and attacker can send or\nembed (in another page) a specially crafted URL which can allow the attacker\nto execute JavaScript in the context of the local application.\n\nWorkarounds\n-----------\nUntil such time as the patch can be applied, application developers should\ndisable the Actionable Exceptions middleware in their development environment via\na line such as this one in their config/environment/development.rb:\n\n'config.middleware.delete ActionDispatch::ActionableExceptions'\n",
        "cvss_v2": null,
        "cvss_v3": 6.1,
        "cve": "2020-8264",
        "osvdb": null,
        "ghsa": "35mm-cc6r-8fjp",
        "unaffected_versions": [
          "< 6.0.0"
        ],
        "patched_versions": [
          ">= 6.0.3.4"
        ],
        "criticality": "medium"
      }
    },
    {
      "type": "unpatched_gem",
      "gem": {
        "name": "actionpack",
        "version": "6.0.0"
      },
      "advisory": {
        "path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2021-22881.yml",
        "id": "CVE-2021-22881",
        "url": "https://groups.google.com/g/rubyonrails-security/c/zN_3qA26l6E",
        "title": "Possible Open Redirect in Host Authorization Middleware",
        "date": "2021-02-10",
        "description": "There is a possible open redirect vulnerability in the Host Authorization\nmiddleware in Action Pack. This vulnerability has been assigned the CVE\nidentifier CVE-2021-22881.\n\nVersions Affected:  >= 6.0.0\nNot affected:       < 6.0.0\nFixed Versions:     6.1.2.1, 6.0.3.5\n\nImpact\n------\nSpecially crafted \"Host\" headers in combination with certain \"allowed host\"\nformats can cause the Host Authorization middleware in Action Pack to redirect\nusers to a malicious website.\n\nImpacted applications will have allowed hosts with a leading dot.  For\nexample, configuration files that look like this:\n\n'\nconfig.hosts <<  '.tkte.ch'\n'\n\nWhen an allowed host contains a leading dot, a specially crafted Host header\ncan be used to redirect to a malicious website.\n\nWorkarounds\n-----------\nIn the case a patch can't be applied, the following monkey patch can be used\nin an initializer:\n\n'ruby\nmodule ActionDispatch\n  class HostAuthorization\n    private\n      def authorized?(request)\n        valid_host = /\n          \\A\n          (?<host>[a-z0-9.-]+|\\[[a-f0-9]*:[a-f0-9\\.:]+\\])\n          (:\\d+)?\n          \\z\n        /x\n\n        origin_host = valid_host.match(\n          request.get_header(\"HTTP_HOST\").to_s.downcase)\n        forwarded_host = valid_host.match(\n          request.x_forwarded_host.to_s.split(/,\\s?/).last)\n\n        origin_host && @permissions.allows?(origin_host[:host]) && (\n          forwarded_host.nil? || @permissions.allows?(forwarded_host[:host]))\n      end\n  end\nend\n'\n",
"cvss_v2": null,
"cvss_v3": 6.1,
"cve": "2021-22881",
"osvdb": null,
"ghsa": "8877-prq4-9xfw",
"unaffected_versions": [
"< 6.0.0"
],
"patched_versions": [
"~> 6.0.3, >= 6.0.3.5",
">= 6.1.2.1"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionpack",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2021-22885.yml",
"id": "CVE-2021-22885",
"url": "https://groups.google.com/g/rubyonrails-security/c/NiQl-48cXYI",
"title": "Possible Information Disclosure / Unintended Method Execution in Action Pack",
"date": "2021-05-05",
"description": "There is a possible information disclosure / unintended method execution\nvulnerability in Action Pack which has been assigned the CVE identifier\nCVE-2021-22885.\n\nVersions Affected:  >= 2.0.0.\nNot affected:       < 2.0.0.\nFixed Versions:     6.1.3.2, 6.0.3.7, 5.2.4.6, 5.2.6\n\nImpact\n------\nThere is a possible information disclosure / unintended method execution\nvulnerability in Action Pack when using the 'redirect_to' or 'polymorphic_url'\nhelper with untrusted user input.\n\nVulnerable code will look like this:\n\n'\nredirect_to(params[:some_param])\n'\n\nAll users running an affected release should either upgrade or use one of the\nworkarounds immediately.\n\nWorkarounds\n-----------\nTo work around this problem, it is recommended to use an allow list for valid\nparameters passed from the user.  For example:\n\n'\nprivate def check(param)\n  case param\n  when \"valid\"\n    param\n  else\n    \"/\"\n  end\nend\n\ndef index\n  redirect_to(check(params[:some_param]))\nend\n'\n\nOr force the user input to be cast to a string like this:\n\n'\ndef index\n  redirect_to(params[:some_param].to_s)\nend\n'\n",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2021-22885",
"osvdb": null,
"ghsa": "hjg4-8q5f-x6fm",
"unaffected_versions": [
"< 2.0.0"
],
"patched_versions": [
"~> 5.2.4.6",
"~> 5.2.6",
"~> 6.0.3, >= 6.0.3.7",
">= 6.1.3.2"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionpack",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2021-22902.yml",
"id": "CVE-2021-22902",
"url": "https://groups.google.com/g/rubyonrails-security/c/_5ID_ld9u1c",
"title": "Possible Denial of Service vulnerability in Action Dispatch",
"date": "2021-05-05",
"description": "There is a possible Denial of Service vulnerability in the Mime type parser of\nAction Dispatch. This vulnerability has been assigned the CVE identifier\nCVE-2021-22902.\n\nVersions Affected:  >= 6.0.0\nNot affected:       < 6.0.0\nFixed Versions:     6.0.3.7, 6.1.3.2\n\nImpact\n------\nThere is a possible Denial of Service vulnerability in Action Dispatch.\nCarefully crafted Accept headers can cause the mime type parser in Action\nDispatch to do catastrophic backtracking in the regular expression engine.\n\nWorkarounds\n-----------\nThe following monkey patch placed in an initializer can be used to work around\nthe issue:\n\n'ruby\nmodule Mime\n  class Type\n    MIME_REGEXP = /\\A(?:\\*\\/\\*|#{MIME_NAME}\\/(?:\\*|#{MIME_NAME})(?>\\s*#{MIME_PARAMETER}\\s*)*)\\z/\n  end\nend\n'\n",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2021-22902",
"osvdb": null,
"ghsa": "g8ww-46x2-2p65",
"unaffected_versions": [
"< 6.0.0"
],
"patched_versions": [
"~> 6.0.3, >= 6.0.3.7",
">= 6.1.3.2"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionpack",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2021-22904.yml",
"id": "CVE-2021-22904",
"url": "https://groups.google.com/g/rubyonrails-security/c/Pf1TjkOBdyQ",
"title": "Possible DoS Vulnerability in Action Controller Token Authentication",
"date": "2021-05-05",
"description": "There is a possible DoS vulnerability in the Token Authentication logic in\nAction Controller.  This vulnerability has been assigned the CVE identifier\nCVE-2021-22904.\n\nVersions Affected:  >= 4.0.0\nNot affected:       < 4.0.0\nFixed Versions:     6.1.3.2, 6.0.3.7, 5.2.4.6, 5.2.6\n\nImpact\n------\nImpacted code uses 'authenticate_or_request_with_http_token' or\n'authenticate_with_http_token' for request authentication.  Impacted code will\nlook something like this:\n\n'\nclass PostsController < ApplicationController\n  before_action :authenticate\n\n  private\n\n  def authenticate\n    authenticate_or_request_with_http_token do |token, options|\n      # ...\n    end\n  end\nend\n'\n\nAll users running an affected release should either upgrade or use one of the\nworkarounds immediately.\n\nReleases\n--------\nThe fixed releases are available at the normal locations.\n\nWorkarounds\n-----------\nThe following monkey patch placed in an initializer can be used to work around\nthe issue:\n\n'ruby\nmodule ActionController::HttpAuthentication::Token\n  AUTHN_PAIR_DELIMITERS = /(?:,|;|\\t)/\nend\n'\n",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2021-22904",
"osvdb": null,
"ghsa": "7wjx-3g7j-8584",
"unaffected_versions": [
"< 4.0.0"
],
"patched_versions": [
"~> 5.2.4.6",
"~> 5.2.6",
"~> 6.0.3, >= 6.0.3.7",
">= 6.1.3.2"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionpack",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2021-22942.yml",
"id": "CVE-2021-22942",
"url": "https://groups.google.com/g/rubyonrails-security/c/wB5tRn7h36c",
"title": "Possible Open Redirect in Host Authorization Middleware",
"date": "2021-08-19",
"description": "There is a possible open redirect vulnerability in the Host Authorization\nmiddleware in Action Pack. This vulnerability has been assigned the CVE\nidentifier CVE-2021-22942.\n\nVersions Affected: >= 6.0.0.\nNot affected: < 6.0.0\nFixed Versions: 6.1.4.1, 6.0.4.1\n\nImpact\n------\n\nSpecially crafted “X-Forwarded-Host” headers in combination with certain\n“allowed host” formats can cause the Host Authorization middleware in\nAction Pack to redirect users to a malicious website.\n\nImpacted applications will have allowed hosts with a leading dot.\nFor example, configuration files that look like this:\n\n'ruby\nconfig.hosts <<  '.EXAMPLE.com'\n'\n\nWhen an allowed host contains a leading dot, a specially crafted\nHost header can be used to redirect to a malicious website.\n\nThis vulnerability is similar to CVE-2021-22881, but CVE-2021-22881 did not\ntake in to account domain name case sensitivity.\n\nReleases\n--------\n\nThe fixed releases are available at the normal locations.\n\nWorkarounds\n-----------\n\nIn the case a patch can’t be applied, the following monkey patch can be\nused in an initializer:\n\n'ruby\nmodule ActionDispatch\n  class HostAuthorization\n    HOSTNAME = /[a-z0-9.-]+|\\[[a-f0-9]*:[a-f0-9.:]+\\]/i\n    VALID_ORIGIN_HOST = /\\A(#{HOSTNAME})(?::\\d+)?\\z/\n    VALID_FORWARDED_HOST = /(?:\\A|,[ ]?)(#{HOSTNAME})(?::\\d+)?\\z/\n\n    private\n      def authorized?(request)\n        origin_host =\n          request.get_header(\"HTTP_HOST\")&.slice(VALID_ORIGIN_HOST, 1) || \"\"\n        forwarded_host =\n          request.x_forwarded_host&.slice(VALID_FORWARDED_HOST, 1) || \"\"\n        @permissions.allows?(origin_host) &&\n          (forwarded_host.blank? || @permissions.allows?(forwarded_host))\n      end\n  end\nend\n'\n",
"cvss_v2": null,
"cvss_v3": 7.6,
"cve": "2021-22942",
"osvdb": null,
"ghsa": "2rqw-v265-jf8c",
"unaffected_versions": [
"< 6.0.0"
],
"patched_versions": [
"~> 6.0.4, >= 6.0.4.1",
">= 6.1.4.1"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionpack",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2021-44528.yml",
"id": "CVE-2021-44528",
"url": "https://groups.google.com/g/ruby-security-ann/c/vG9gz3nk1pM/m/7-NU4MNrDAAJ",
"title": "Possible Open Redirect in Host Authorization Middleware",
"date": "2021-12-14",
"description": "There is a possible open redirect vulnerability in the Host Authorization\nmiddleware in Action Pack.\n\nSpecially crafted \"X-Forwarded-Host\" headers in combination with certain\n\"allowed host\" formats can cause the Host Authorization middleware in Action\nPack to redirect users to a malicious website.\n\nImpacted applications will have allowed hosts with a leading dot. For example,\nconfiguration files that look like this:\n\n'\nconfig.hosts <<  '.EXAMPLE.com'\n'\n\nWhen an allowed host contains a leading dot, a specially crafted Host header\ncan be used to redirect to a malicious website.\n\nThis vulnerability is similar to CVE-2021-22881 and CVE-2021-22942.\n\nReleases\n--------\nThe fixed releases are available at the normal locations.\n\nPatches\n-------\nTo aid users who aren't able to upgrade immediately we have provided patches for\nthe two supported release series. They are in git-am format and consist of a\nsingle changeset.\n\n* 6-0-host-authorzation-open-redirect.patch - Patch for 6.0 series\n* 6-1-host-authorzation-open-redirect.patch - Patch for 6.1 series\n* 7-0-host-authorzation-open-redirect.patch - Patch for 7.0 series\n\nPlease note that only the 6.1.Z, 6.0.Z, and 5.2.Z series are supported at\npresent. Users of earlier unsupported releases are advised to upgrade as soon\nas possible as we cannot guarantee the continued availability of security\nfixes for unsupported releases.",
"cvss_v2": null,
"cvss_v3": 6.1,
"cve": "2021-44528",
"osvdb": null,
"ghsa": "qphc-hf5q-v8fc",
"unaffected_versions": [
"< 6.0.0"
],
"patched_versions": [
"~> 6.0.4, >= 6.0.4.2",
"~> 6.1.4, >= 6.1.4.2",
">= 7.0.0.rc2"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionpack",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionpack/CVE-2022-23633.yml",
"id": "CVE-2022-23633",
"url": "https://groups.google.com/g/ruby-security-ann/c/FkTM-_7zSNA/m/K2RiMJBlBAAJ",
"title": "Possible exposure of information vulnerability in Action Pack",
"date": "2022-02-11",
"description": "## Impact\n\nUnder certain circumstances response bodies will not be closed, for example a\nbug in a webserver (https://github.com/puma/puma/pull/2812) or a bug in a Rack\nmiddleware. In the event a response is not notified of a 'close',\n'ActionDispatch::Executor' will not know to reset thread local state for the\nnext request. This can lead to data being leaked to subsequent requests,\nespecially when interacting with 'ActiveSupport::CurrentAttributes'.\n\nUpgrading to the FIXED versions of Rails will ensure mitigation if this issue\neven in the context of a buggy webserver or middleware implementation.\n\n## Patches\n\nThis has been fixed in Rails 7.0.2.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2.\n\n## Workarounds\n\nUpgrading is highly recommended, but to work around this problem the following\nmiddleware can be used:\n\n'\nclass GuardedExecutor < ActionDispatch::Executor\n  def call(env)\n    ensure_completed!\n    super\n  end\n\n  private\n\n    def ensure_completed!\n      @executor.new.complete! if @executor.active?\n    end\nend\n\n# Ensure the guard is inserted before ActionDispatch::Executor\nRails.application.configure do\n  config.middleware.swap ActionDispatch::Executor, GuardedExecutor, executor\nend\n'",
"cvss_v2": null,
"cvss_v3": 7.4,
"cve": "2022-23633",
"osvdb": null,
"ghsa": "wh98-p28r-vrc9",
"unaffected_versions": [
"< 5.0.0"
],
"patched_versions": [
"~> 5.2.6, >= 5.2.6.2",
"~> 6.0.4, >= 6.0.4.6",
"~> 6.1.4, >= 6.1.4.6",
">= 7.0.2.2"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionview",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionview/CVE-2020-15169.yml",
"id": "CVE-2020-15169",
"url": "https://groups.google.com/g/rubyonrails-security/c/b-C9kSGXYrc",
"title": "Potential XSS vulnerability in Action View",
"date": "2020-09-09",
"description": "There is a potential Cross-Site Scripting (XSS) vulnerability in Action\nView's translation helpers. Views that allow the user to control the\ndefault (not found) value of the 't' and 'translate' helpers could be\nsusceptible to XSS attacks.\n\nImpact\n------\n\nWhen an HTML-unsafe string is passed as the default for a missing\ntranslation key [named 'html' or ending in '_html'](https://guides.rubyonrails.org/i18n.html#using-safe-html-translations),\nthe default string is incorrectly marked as HTML-safe and not escaped.\nVulnerable code may look like the following examples:\n\n'erb\n<%# The welcome_html translation is not defined for the current locale: %>\n<%= t(\"welcome_html\", default: untrusted_user_controlled_string) %>\n\n<%# Neither the title.html translation nor the missing.html translation is defined for the current locale: %>\n<%= t(\"title.html\", default: [:\"missing.html\", untrusted_user_controlled_string]) %>\n'\n\nWorkarounds\n-----------\nImpacted users who can’t upgrade to a patched Rails version can avoid\nthis issue by manually escaping default translations with the\n'html_escape' helper (aliased as 'h'):\n\n'erb\n<%= t(\"welcome_html\", default: h(untrusted_user_controlled_string)) %>\n'\n",
"cvss_v2": null,
"cvss_v3": 5.4,
"cve": "2020-15169",
"osvdb": null,
"ghsa": "cfjv-5498-mph5",
"unaffected_versions": [

],
"patched_versions": [
"~> 5.2.4, >= 5.2.4.4",
">= 6.0.3.3"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionview",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionview/CVE-2020-5267.yml",
"id": "CVE-2020-5267",
"url": "https://groups.google.com/forum/#!topic/rubyonrails-security/55reWMM_Pg8",
"title": "Possible XSS vulnerability in ActionView",
"date": "2020-03-19",
"description": "There is a possible XSS vulnerability in ActionView's JavaScript literal\nescape helpers.  Views that use the 'j' or 'escape_javascript' methods\nmay be susceptible to XSS attacks.\n\nVersions Affected:  All.\nNot affected:       None.\nFixed Versions:     6.0.2.2, 5.2.4.2\n\nImpact\n------\nThere is a possible XSS vulnerability in the 'j' and 'escape_javascript'\nmethods in ActionView.  These methods are used for escaping JavaScript string\nliterals.  Impacted code will look something like this:\n\n'erb\n<script>let a = '<%= j unknown_input %>'</script>\n'\n\nor\n\n'erb\n<script>let a = '<%= escape_javascript unknown_input %>'</script>\n'\n\nReleases\n--------\nThe 6.0.2.2 and 5.2.4.2 releases are available at the normal locations.\n\nWorkarounds\n-----------\nFor those that can't upgrade, the following monkey patch may be used:\n\n'ruby\nActionView::Helpers::JavaScriptHelper::JS_ESCAPE_MAP.merge!(\n  {\n    \"'\" => \"\\\\'\",\n    \"$\" => \"\\\\$\"\n  }\n)\n\nmodule ActionView::Helpers::JavaScriptHelper\n  alias :old_ej :escape_javascript\n  alias :old_j :j\n\n  def escape_javascript(javascript)\n    javascript = javascript.to_s\n    if javascript.empty?\n      result = \"\"\n    else\n      result = javascript.gsub(/(\\\\|<\\/|\\r\\n|\\342\\200\\250|\\342\\200\\251|[\\n\\r\"']|[']|[$])/u, JS_ESCAPE_MAP)\n    end\n    javascript.html_safe? ? result.html_safe : result\n  end\n\n  alias :j :escape_javascript\nend\n'\n",
"cvss_v2": null,
"cvss_v3": 4.0,
"cve": "2020-5267",
"osvdb": null,
"ghsa": "65cv-r6x7-79hv",
"unaffected_versions": [

],
"patched_versions": [
"~> 5.2.4, >= 5.2.4.2",
">= 6.0.2.2"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "actionview",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/actionview/CVE-2020-8167.yml",
"id": "CVE-2020-8167",
"url": "https://groups.google.com/forum/#!topic/rubyonrails-security/x9DixQDG9a0",
"title": "CSRF Vulnerability in rails-ujs",
"date": "2020-05-18",
"description": "There is an vulnerability in rails-ujs that allows attackers to send\nCSRF tokens to wrong domains.\n\nVersions Affected:  rails <= 6.0.3\nNot affected:       Applications which don't use rails-ujs.\nFixed Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1\n\nImpact\n------\n\nThis is a regression of CVE-2015-1840.\n\nIn the scenario where an attacker might be able to control the href attribute of an anchor tag or\nthe action attribute of a form tag that will trigger a POST action, the attacker can set the\nhref or action to a cross-origin URL, and the CSRF token will be sent.\n\nWorkarounds\n-----------\n\nTo work around this problem, change code that allows users to control the href attribute of an anchor\ntag or the action attribute of a form tag to filter the user parameters.\n\nFor example, code like this:\n\n    link_to params\n\nto code like this:\n\n    link_to filtered_params\n\n    def filtered_params\n      # Filter just the parameters that you trust\n    end\n",
"cvss_v2": null,
"cvss_v3": 6.5,
"cve": "2020-8167",
"osvdb": null,
"ghsa": "xq5j-gw7f-jgj8",
"unaffected_versions": [

],
"patched_versions": [
"~> 5.2.4, >= 5.2.4.3",
">= 6.0.3.1"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "activerecord",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/activerecord/CVE-2021-22880.yml",
"id": "CVE-2021-22880",
"url": "https://groups.google.com/g/rubyonrails-security/c/ZzUqCh9vyhI",
"title": "Possible DoS Vulnerability in Active Record PostgreSQL adapter",
"date": "2021-02-10",
"description": "There is a possible DoS vulnerability in the PostgreSQL adapter in Active\nRecord. This vulnerability has been assigned the CVE identifier CVE-2021-22880.\n\nVersions Affected:  >= 4.2.0\nNot affected:       < 4.2.0\nFixed Versions:     6.1.2.1, 6.0.3.5, 5.2.4.5\n\nImpact\n------\nCarefully crafted input can cause the input validation in the \"money\" type of\nthe PostgreSQL adapter in Active Record to spend too much time in a regular\nexpression, resulting in the potential for a DoS attack.\n\nThis only impacts Rails applications that are using PostgreSQL along with\nmoney type columns that take user input.\n\nWorkarounds\n-----------\nIn the case a patch can't be applied, the following monkey patch can be used\nin an initializer:\n\n'\nmodule ActiveRecord\n  module ConnectionAdapters\n    module PostgreSQL\n      module OID # :nodoc:\n        class Money < Type::Decimal # :nodoc:\n          def cast_value(value)\n            return value unless ::String === value\n\n            value = value.sub(/^\\((.+)\\)$/, '-\\1') # (4)\n            case value\n            when /^-?\\D*+[\\d,]+\\.\\d{2}$/  # (1)\n              value.gsub!(/[^-\\d.]/, \"\")\n            when /^-?\\D*+[\\d.]+,\\d{2}$/  # (2)\n              value.gsub!(/[^-\\d,]/, \"\").sub!(/,/, \".\")\n            end\n\n            super(value)\n          end\n        end\n      end\n    end\n  end\nend\n'\n",
"cvss_v2": null,
"cvss_v3": 5.3,
"cve": "2021-22880",
"osvdb": null,
"ghsa": "8hc4-xxm3-5ppp",
"unaffected_versions": [
"< 4.2.0"
],
"patched_versions": [
"~> 5.2.4, >= 5.2.4.5",
"~> 6.0.3, >= 6.0.3.5",
">= 6.1.2.1"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "activestorage",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/activestorage/CVE-2020-8162.yml",
"id": "CVE-2020-8162",
"url": "https://groups.google.com/forum/#!topic/rubyonrails-security/PjU3946mreQ",
"title": "Circumvention of file size limits in ActiveStorage",
"date": "2020-05-18",
"description": "There is a vulnerability in ActiveStorage's S3 adapter that allows the Content-Length of a\ndirect file upload to be modified by an end user.\n\nVersions Affected:  rails < 5.2.4.2, rails < 6.0.3.1\nNot affected:       Applications that do not use the direct upload functionality of the ActiveStorage S3 adapter.\nFixed Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1\n\nImpact\n------\n\nUtilizing this vulnerability, an attacker can control the Content-Length of an S3 direct upload URL without receiving a\nnew signature from the server. This could be used to bypass controls in place on the server to limit upload size.\n\nWorkarounds\n-----------\n\nThis is a low-severity security issue. As such, no workaround is necessarily\nuntil such time as the application can be upgraded.\n",
"cvss_v2": null,
"cvss_v3": null,
"cve": "2020-8162",
"osvdb": null,
"ghsa": "m42x-37p3-fv5w",
"unaffected_versions": [

],
"patched_versions": [
"~> 5.2.4, >= 5.2.4.3",
">= 6.0.3.1"
],
"criticality": null
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "activestorage",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/activestorage/CVE-2022-21831.yml",
"id": "CVE-2022-21831",
"url": "https://groups.google.com/g/rubyonrails-security/c/n-p-W1yxatI",
"title": "Possible code injection vulnerability in Rails / Active Storage",
"date": "2022-03-08",
"description": "There is a possible code injection vulnerability in the Active Storage module\nof Rails. This vulnerability has been assigned the CVE identifier\nCVE-2022-21831.\n\nVersions Affected:  >= 5.2.0\nNot affected:       < 5.2.0\nFixed Versions:     7.0.2.3, 6.1.4.7, 6.0.4.7, 5.2.6.3\n\nImpact\n------\nThere is a possible code injection vulnerability in the Active Storage module\nof Rails.  This vulnerability impacts applications that use Active Storage\nwith the image_processing processing in addition to the mini_magick back end\nfor image_processing.\n\nVulnerable code will look something similar to this:\n\n'ruby\n<%= image_tag blob.variant(params[:t] => params[:v]) %>\n'\n\nWhere the transformation method or its arguments are untrusted arbitrary\ninput.\n\nAll users running an affected release should either upgrade or use one of the\nworkarounds immediately.\n\nWorkarounds\n-----------\nTo work around this issue, applications should implement a strict allow-list\non accepted transformation methods or arguments.  Additionally, a strict image\nmagick security policy will help mitigate this issue.\n\n  https://imagemagick.org/script/security-policy.php\n",
"cvss_v2": null,
"cvss_v3": null,
"cve": "2022-21831",
"osvdb": null,
"ghsa": "w749-p3v6-hccq",
"unaffected_versions": [
"< 5.2.0"
],
"patched_versions": [
"~> 5.2.6, >= 5.2.6.3",
"~> 6.0.4, >= 6.0.4.7",
"~> 6.1.4, >= 6.1.4.7",
">= 7.0.2.3"
],
"criticality": null
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "activesupport",
"version": "6.0.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/activesupport/CVE-2020-8165.yml",
"id": "CVE-2020-8165",
"url": "https://groups.google.com/forum/#!topic/rubyonrails-security/bv6fW4S0Y1c",
"title": "Potentially unintended unmarshalling of user-provided objects in MemCacheStore and RedisCacheStore",
"date": "2020-05-18",
"description": "There is potentially unexpected behaviour in the MemCacheStore and RedisCacheStore where, when\nuntrusted user input is written to the cache store using the 'raw: true' parameter, re-reading the result\nfrom the cache can evaluate the user input as a Marshalled object instead of plain text. Vulnerable code looks like:\n\n'\ndata = cache.fetch(\"demo\", raw: true) { untrusted_string }\n'\n\nVersions Affected:  rails < 5.2.5, rails < 6.0.4\nNot affected:       Applications not using MemCacheStore or RedisCacheStore. Applications that do not use the 'raw' option when storing untrusted user input.\nFixed Versions:     rails >= 5.2.4.3, rails >= 6.0.3.1\n\nImpact\n------\n\nUnmarshalling of untrusted user input can have impact up to and including RCE. At a minimum,\nthis vulnerability allows an attacker to inject untrusted Ruby objects into a web application.\n\nIn addition to upgrading to the latest versions of Rails, developers should ensure that whenever\nthey are calling 'Rails.cache.fetch' they are using consistent values of the 'raw' parameter for both\nreading and writing, especially in the case of the RedisCacheStore which does not, prior to these changes,\ndetect if data was serialized using the raw option upon deserialization.\n\nWorkarounds\n-----------\n\nIt is recommended that application developers apply the suggested patch or upgrade to the latest release as\nsoon as possible. If this is not possible, we recommend ensuring that all user-provided strings cached using\nthe 'raw' argument should be double-checked to ensure that they conform to the expected format.\n",
"cvss_v2": null,
"cvss_v3": null,
"cve": "2020-8165",
"osvdb": null,
"ghsa": "2p68-f74v-9wc6",
"unaffected_versions": [

],
"patched_versions": [
"~> 5.2.4, >= 5.2.4.3",
">= 6.0.3.1"
],
"criticality": null
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "addressable",
"version": "2.6.0"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/addressable/CVE-2021-32740.yml",
"id": "CVE-2021-32740",
"url": "https://github.com/advisories/GHSA-jxhc-q857-3j6g",
"title": "Regular Expression Denial of Service in Addressable templates",
"date": "2021-07-12",
"description": "Within the URI template implementation in Addressable, a maliciously crafted template may result in uncontrolled resource consumption,\nleading to denial of service when matched against a URI. In typical usage, templates would not normally be read from untrusted user input,\nbut nonetheless, no previous security advisory for Addressable has cautioned against doing this.\nUsers of the parsing capabilities in Addressable but not the URI template capabilities are unaffected.\n",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2021-32740",
"osvdb": null,
"ghsa": "jxhc-q857-3j6g",
"unaffected_versions": [
"< 2.3.0"
],
"patched_versions": [
">= 2.8.0"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "loofah",
"version": "2.2.3"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/loofah/CVE-2019-15587.yml",
"id": "CVE-2019-15587",
"url": "https://github.com/flavorjones/loofah/issues/171",
"title": "Loofah XSS Vulnerability",
"date": "2019-10-22",
"description": "In the Loofah gem, through v2.3.0, unsanitized JavaScript may occur in\nsanitized output when a crafted SVG element is republished.\n",
"cvss_v2": null,
"cvss_v3": 6.4,
"cve": "2019-15587",
"osvdb": null,
"ghsa": "c3gv-9cxf-6f57",
"unaffected_versions": [

],
"patched_versions": [
">= 2.3.1"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "nokogiri",
"version": "1.10.4"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/nokogiri/CVE-2019-13117.yml",
"id": "CVE-2019-13117",
"url": "https://github.com/sparklemotion/nokogiri/issues/1943",
"title": "Nokogiri gem, via libxslt, is affected by multiple vulnerabilities",
"date": "2019-10-31",
"description": "Nokogiri v1.10.5 has been released.\n\nThis is a security release. It addresses three CVEs in upstream libxml2,\nfor which details are below.\n\nIf you're using your distro's system libraries, rather than Nokogiri's\nvendored libraries, there's no security need to upgrade at this time,\nthough you may want to check with your distro whether they've patched this\n(Canonical has patched Ubuntu packages). Note that libxslt 1.1.34 addresses\nthese vulnerabilities.\n\nFull details about the security update are available in Github Issue\n[#1943] https://github.com/sparklemotion/nokogiri/issues/1943.\n\n---\n\nCVE-2019-13117\n\nhttps://people.canonical.com/~ubuntu-security/cve/2019/CVE-2019-13117.html\n\nPriority: Low\n\nDescription: In numbers.c in libxslt 1.1.33, an xsl:number with certain format strings\ncould lead to a uninitialized read in xsltNumberFormatInsertNumbers. This\ncould allow an attacker to discern whether a byte on the stack contains the\ncharacters A, a, I, i, or 0, or any other character.\n\nPatched with commit https://gitlab.gnome.org/GNOME/libxslt/commit/c5eb6cf3aba0af048596106ed839b4ae17ecbcb1\n\n---\n\nCVE-2019-13118\n\nhttps://people.canonical.com/~ubuntu-security/cve/2019/CVE-2019-13118.html\n\nPriority: Low\n\nDescription: In numbers.c in libxslt 1.1.33, a type holding grouping characters of an\nxsl:number instruction was too narrow and an invalid character/length\ncombination could be passed to xsltNumberFormatDecimal, leading to a read\nof uninitialized stack data\n\nPatched with commit https://gitlab.gnome.org/GNOME/libxslt/commit/6ce8de69330783977dd14f6569419489875fb71b\n\n---\n\nCVE-2019-18197\n\nhttps://people.canonical.com/~ubuntu-security/cve/2019/CVE-2019-18197.html\n\nPriority: Medium\n\nDescription: In xsltCopyText in transform.c in libxslt 1.1.33, a pointer variable isn't\nreset under certain circumstances. If the relevant memory area happened to\nbe freed and reused in a certain way, a bounds check could fail and memory\noutside a buffer could be written to, or uninitialized data could be\ndisclosed.\n\nPatched with commit https://gitlab.gnome.org/GNOME/libxslt/commit/2232473733b7313d67de8836ea3b29eec6e8e285\n",
"cvss_v2": null,
"cvss_v3": null,
"cve": "2019-13117",
"osvdb": null,
"ghsa": null,
"unaffected_versions": [

],
"patched_versions": [
">= 1.10.5"
],
"criticality": null
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "nokogiri",
"version": "1.10.4"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/nokogiri/CVE-2020-26247.yml",
"id": "CVE-2020-26247",
"url": "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-vr8q-g5c7-m54m",
"title": "Nokogiri::XML::Schema trusts input by default, exposing risk of an XXE vulnerability",
"date": "2020-12-30",
"description": "### Description\n\nIn Nokogiri versions <= 1.11.0.rc3, XML Schemas parsed by 'Nokogiri::XML::Schema'\nare **trusted** by default, allowing external resources to be accessed over the\nnetwork, potentially enabling XXE or SSRF attacks.\n\nThis behavior is counter to\nthe security policy followed by Nokogiri maintainers, which is to treat all input\nas **untrusted** by default whenever possible.\n\nPlease note that this security\nfix was pushed into a new minor version, 1.11.x, rather than a patch release to\nthe 1.10.x branch, because it is a breaking change for some schemas and the risk\nwas assessed to be \"Low Severity\".\n\n### Affected Versions\n\nNokogiri '<= 1.10.10' as well as prereleases '1.11.0.rc1', '1.11.0.rc2', and '1.11.0.rc3'\n\n### Mitigation\n\nThere are no known workarounds for affected versions. Upgrade to Nokogiri\n'1.11.0.rc4' or later.\n\nIf, after upgrading to '1.11.0.rc4' or later, you wish\nto re-enable network access for resolution of external resources (i.e., return to\nthe previous behavior):\n\n1. Ensure the input is trusted. Do not enable this option\nfor untrusted input.\n2. When invoking the 'Nokogiri::XML::Schema' constructor,\npass as the second parameter an instance of 'Nokogiri::XML::ParseOptions' with the\n'NONET' flag turned off.\n\nSo if your previous code was:\n\n' ruby\n# in v1.11.0.rc3 and earlier, this call allows resources to be accessed over the network\n# but in v1.11.0.rc4 and later, this call will disallow network access for external resources\nschema = Nokogiri::XML::Schema.new(schema)\n\n# in v1.11.0.rc4 and later, the following is equivalent to the code above\n# (the second parameter is optional, and this demonstrates its default value)\nschema = Nokogiri::XML::Schema.new(schema, Nokogiri::XML::ParseOptions::DEFAULT_SCHEMA)\n'\n\nThen you can add the second parameter to indicate that the input is trusted by changing it to:\n\n' ruby\n# in v1.11.0.rc3 and earlier, this would raise an ArgumentError\n# but in v1.11.0.rc4 and later, this allows resources to be accessed over the network\nschema = Nokogiri::XML::Schema.new(trusted_schema, Nokogiri::XML::ParseOptions.new.nononet)\n'",
"cvss_v2": null,
"cvss_v3": 2.6,
"cve": "2020-26247",
"osvdb": null,
"ghsa": "vr8q-g5c7-m54m",
"unaffected_versions": [

],
"patched_versions": [
">= 1.11.0.rc4"
],
"criticality": "low"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "nokogiri",
"version": "1.10.4"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/nokogiri/CVE-2020-7595.yml",
"id": "CVE-2020-7595",
"url": "https://github.com/sparklemotion/nokogiri/issues/1992",
"title": "libxml2 2.9.10 has an infinite loop in a certain end-of-file situation",
"date": "2020-02-12",
"description": "\nNokogiri has backported the patch for CVE-2020-7595 into its vendored version\nof libxml2, and released this as v1.10.8\n\nCVE-2020-7595 has not yet been addressed in an upstream libxml2 release, and\nso Nokogiri versions <= v1.10.7 are vulnerable.",
"cvss_v2": 5.0,
"cvss_v3": 7.5,
"cve": "2020-7595",
"osvdb": null,
"ghsa": "7553-jr98-vx47",
"unaffected_versions": [

],
"patched_versions": [
">= 1.10.8"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "nokogiri",
"version": "1.10.4"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/nokogiri/CVE-2021-41098.yml",
"id": "CVE-2021-41098",
"url": "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-2rr5-8q37-2w7h",
"title": "Improper Restriction of XML External Entity Reference (XXE) in Nokogiri on JRuby",
"date": "2021-09-27",
"description": "### Severity\n\nThe Nokogiri maintainers have evaluated this as [**High Severity** 7.5 (CVSS3.0)](https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C/MAV:N/MAC:L) for JRuby users. (This security advisory does not apply to CRuby users.)\n\n### Impact\n\nIn Nokogiri v1.12.4 and earlier, **on JRuby only**, the SAX parser resolves external entities by default.\n\nUsers of Nokogiri on JRuby who parse untrusted documents using any of these classes are affected:\n\n- Nokogiri::XML::SAX::Parser\n- Nokogiri::HTML4::SAX::Parser or its alias Nokogiri::HTML::SAX::Parser\n- Nokogiri::XML::SAX::PushParser\n- Nokogiri::HTML4::SAX::PushParser or its alias Nokogiri::HTML::SAX::PushParser\n\n### Mitigation\n\nJRuby users should upgrade to Nokogiri v1.12.5 or later. There are no workarounds available for v1.12.4 or earlier.\n\nCRuby users are not affected.",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2021-41098",
"osvdb": null,
"ghsa": "2rr5-8q37-2w7h",
"unaffected_versions": [

],
"patched_versions": [
">= 1.12.5"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "nokogiri",
"version": "1.10.4"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/nokogiri/GHSA-7rrm-v45f-jp64.yml",
"id": "GHSA-7rrm-v45f-jp64",
"url": "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-7rrm-v45f-jp64",
"title": "Update packaged dependency libxml2 from 2.9.10 to 2.9.12",
"date": "2021-05-17",
"description": "### Summary\n\nNokogiri v1.11.4 updates the vendored libxml2 from v2.9.10 to v2.9.12 which addresses:\n\n- [CVE-2019-20388](https://security.archlinux.org/CVE-2019-20388) (Medium severity)\n- [CVE-2020-24977](https://security.archlinux.org/CVE-2020-24977) (Medium severity)\n- [CVE-2021-3517](https://security.archlinux.org/CVE-2021-3517) (Medium severity)\n- [CVE-2021-3518](https://security.archlinux.org/CVE-2021-3518) (Medium severity)\n- [CVE-2021-3537](https://security.archlinux.org/CVE-2021-3537) (Low severity)\n- [CVE-2021-3541](https://security.archlinux.org/CVE-2021-3541) (Low severity)\n\nNote that two additional CVEs were addressed upstream but are not relevant to this release. [CVE-2021-3516](https://security.archlinux.org/CVE-2021-3516) via 'xmllint' is not present in Nokogiri, and [CVE-2020-7595](https://security.archlinux.org/CVE-2020-7595) has been patched in Nokogiri since v1.10.8 (see #1992).\n\nPlease note that this advisory only applies to the CRuby implementation of Nokogiri '< 1.11.4', and only if the packaged version of libxml2 is being used. If you've overridden defaults at installation time to use system libraries instead of packaged libraries, you should instead pay attention to your distro's 'libxml2' release announcements.\n\n\n### Mitigation\n\nUpgrade to Nokogiri '>= 1.11.4'.\n\n\n### Impact\n\nI've done a brief analysis of the published CVEs that are addressed in this upstream release. The libxml2 maintainers have not released a canonical set of CVEs, and so this list is pieced together from secondary sources and may be incomplete.\n\nAll information below is sourced from [security.archlinux.org](https://security.archlinux.org), which appears to have the most up-to-date information as of this analysis.\n\n#### [CVE-2019-20388](https://security.archlinux.org/CVE-2019-20388)\n\n- **Severity**: Medium\n- **Type**: Denial of service\n- **Description**: A memory leak was found in the xmlSchemaValidateStream function of libxml2. Applications that use this library may be vulnerable to memory not being freed leading to a denial of service.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/commit/7ffcd44d7e6c46704f8af0321d9314cd26e0e18a\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri < v1.11.4.\n\n\n#### [CVE-2020-7595](https://security.archlinux.org/CVE-2020-7595)\n\n- **Severity**: Medium\n- **Type**: Denial of service\n- **Description**: xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file situation.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/commit/0e1a49c8907645d2e155f0d89d4d9895ac5112b5\n\nThis has been patched in Nokogiri since v1.10.8 (see #1992).\n\n\n#### [CVE-2020-24977](https://security.archlinux.org/CVE-2020-24977)\n\n- **Severity**: Medium\n- **Type**: Information disclosure\n- **Description**: GNOME project libxml2 <= 2.9.10 has a global buffer over-read vulnerability in xmlEncodeEntitiesInternal at libxml2/entities.c.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/commit/50f06b3efb638efb0abd95dc62dca05ae67882c2\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri < v1.11.4.\n\n\n#### [CVE-2021-3516](https://security.archlinux.org/CVE-2021-3516)\n\n- **Severity**: Medium\n- **Type**: Arbitrary code execution (no remote vector)\n- **Description**: A use-after-free security issue was found libxml2 before version 2.9.11 when \"xmllint --html --push\" is used to process crafted files.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/230\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/1358d157d0bd83be1dfe356a69213df9fac0b539\n\nVerified that the fix commit first appears in v2.9.11. This vector does not exist within Nokogiri, which does not ship 'xmllint'.\n\n\n#### [CVE-2021-3517](https://security.archlinux.org/CVE-2021-3517)\n\n- **Severity**: Medium\n- **Type**: Arbitrary code execution\n- **Description**: A heap-based buffer overflow was found in libxml2 before version 2.9.11 when processing truncated UTF-8 input.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/235\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri < v1.11.4.\n\n\n#### [CVE-2021-3518](https://security.archlinux.org/CVE-2021-3518)\n\n- **Severity**: Medium\n- **Type**: Arbitrary code execution\n- **Description**: A use-after-free security issue was found in libxml2 before version 2.9.11 in xmlXIncludeDoProcess() in xinclude.c when processing crafted files.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/237\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/1098c30a040e72a4654968547f415be4e4c40fe7\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri < v1.11.4.\n\n\n#### [CVE-2021-3537](https://security.archlinux.org/CVE-2021-3537)\n\n- **Severity**: Low\n- **Type**: Denial of service\n- **Description**: It was found that libxml2 before version 2.9.11 did not propagate errors while parsing XML mixed content, causing a NULL dereference. If an untrusted XML document was parsed in recovery mode and post-validated, the flaw could be used to crash the application.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/243\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/babe75030c7f64a37826bb3342317134568bef61\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri < v1.11.4.\n\n\n#### [CVE-2021-3541](https://security.archlinux.org/CVE-2021-3541)\n\n- **Severity**: Low\n- **Type**: Denial of service\n- **Description**: A security issue was found in libxml2 before version 2.9.11. Exponential entity expansion attack its possible bypassing all existing protection mechanisms and leading to denial of service.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/8598060bacada41a0eb09d95c97744ff4e428f8e\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri < v1.11.4, however Nokogiri's default parse options prevent the attack from succeeding (it is necessary to opt into 'DTDLOAD' which is off by default).\n\nFor more details supporting this analysis of this CVE, please visit #2233.\n",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": null,
"osvdb": null,
"ghsa": "7rrm-v45f-jp64",
"unaffected_versions": [

],
"patched_versions": [
">= 1.11.4"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "nokogiri",
"version": "1.10.4"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/nokogiri/GHSA-fq42-c5rg-92c2.yml",
"id": "GHSA-fq42-c5rg-92c2",
"url": "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-fq42-c5rg-92c2",
"title": "Update packaged libxml2 (2.9.12 → 2.9.13) and libxslt (1.1.34 → 1.1.35)",
"date": "2022-02-21",
"description": "## Summary\n\nNokogiri v1.13.2 upgrades two of its packaged dependencies:\n\n* vendored libxml2 from v2.9.12 to v2.9.13\n* vendored libxslt from v1.1.34 to v1.1.35\n\nThose library versions address the following upstream CVEs:\n\n* libxslt: CVE-2021-30560 (CVSS 8.8, High severity)\n* libxml2: CVE-2022-23308 (Unspecified severity, see more information below)\n\nThose library versions also address numerous other issues including performance\nimprovements, regression fixes, and bug fixes, as well as memory leaks and other\nuse-after-free issues that were not assigned CVEs.\n\nPlease note that this advisory only applies to the CRuby implementation of\nNokogiri < 1.13.2, and only if the packaged libraries are being used. If you've\noverridden defaults at installation time to use system libraries instead of\npackaged libraries, you should instead pay attention to your distro's 'libxml2'\nand 'libxslt' release announcements.\n\n## Mitigation\n\nUpgrade to Nokogiri >= 1.13.2.\n\nUsers who are unable to upgrade Nokogiri may also choose a more complicated\nmitigation: compile and link an older version Nokogiri against external libraries\nlibxml2 >= 2.9.13 and libxslt >= 1.1.35, which will also address these same CVEs.\n\n## Impact\n\n* libxslt CVE-2021-30560\n* CVSS3 score: 8.8 (High)\n\nFixed by https://gitlab.gnome.org/GNOME/libxslt/-/commit/50f9c9c\n\nAll versions of libxslt prior to v1.1.35 are affected.\n\nApplications using untrusted XSL stylesheets to transform XML are vulnerable to\na denial-of-service attack and should be upgraded immediately.\n\nlibxml2 CVE-2022-23308\n* As of the time this security advisory was published, there is no officially\npublished information available about this CVE's severity. The above NIST link\ndoes not yet have a published record, and the libxml2 maintainer has declined\nto provide a severity score.\n* Fixed by https://gitlab.gnome.org/GNOME/libxml2/-/commit/652dd12\n* Further explanation is at https://mail.gnome.org/archives/xml/2022-February/msg00015.html\n\nThe upstream commit and the explanation linked above indicate that an application\nmay be vulnerable to a denial of service, memory disclosure, or code execution if\nit parses an untrusted document with parse options 'DTDVALID' set to true, and 'NOENT'\nset to false.\n\nAn analysis of these parse options:\n\n* While 'NOENT' is off by default for Document, DocumentFragment, Reader, and\nSchema parsing, it is on by default for XSLT (stylesheet) parsing in Nokogiri\nv1.12.0 and later.\n* 'DTDVALID' is an option that Nokogiri does not set for any operations, and so\nthis CVE applies only to applications setting this option explicitly.\n\nIt seems reasonable to assume that any application explicitly setting the parse\noption 'DTDVALID' when parsing untrusted documents is vulnerable and should be\nupgraded immediately.\n",
"cvss_v2": null,
"cvss_v3": 8.8,
"cve": "2021-30560",
"osvdb": null,
"ghsa": "fq42-c5rg-92c2",
"unaffected_versions": [

],
"patched_versions": [
">= 1.13.2"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2019-16770.yml",
"id": "CVE-2019-16770",
"url": "https://github.com/puma/puma/security/advisories/GHSA-7xx3-m584-x994",
"title": "Keepalive thread overload/DoS in puma",
"date": "2019-12-05",
"description": "A poorly-behaved client could use keepalive requests to monopolize\nPuma's reactor and create a denial of service attack.\n\nIf more keepalive connections to Puma are opened than there are\nthreads available, additional connections will wait permanently if\nthe attacker sends requests frequently enough.\n",
"cvss_v2": 6.8,
"cvss_v3": 8.8,
"cve": "2019-16770",
"osvdb": null,
"ghsa": "7xx3-m584-x994",
"unaffected_versions": [

],
"patched_versions": [
"~> 3.12.2",
">= 4.3.1"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2020-11076.yml",
"id": "CVE-2020-11076",
"url": "https://github.com/puma/puma/security/advisories/GHSA-x7jg-6pwg-fx5h",
"title": "HTTP Smuggling via Transfer-Encoding Header in Puma",
"date": "2020-05-22",
"description": "### Impact\n\nBy using an invalid transfer-encoding header, an attacker could\n[smuggle an HTTP response.](https://portswigger.net/web-security/request-smuggling)\n\n### Patches\n\nThe problem has been fixed in Puma 3.12.5 and Puma 4.3.4.",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2020-11076",
"osvdb": null,
"ghsa": "x7jg-6pwg-fx5h",
"unaffected_versions": [

],
"patched_versions": [
"~> 3.12.5",
">= 4.3.4"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2020-11077.yml",
"id": "CVE-2020-11077",
"url": "https://github.com/puma/puma/security/advisories/GHSA-w64w-qqph-5gxm",
"title": "HTTP Smuggling via Transfer-Encoding Header in Puma",
"date": "2020-05-22",
"description": "### Impact\n\nThis is a similar but different vulnerability to the one patched in 3.12.5 and 4.3.4.\n\nA client could smuggle a request through a proxy, causing the proxy to send a response\nback to another unknown client.\n\nIf the proxy uses persistent connections and the client adds another request in via HTTP\npipelining, the proxy may mistake it as the first request's body. Puma, however,\nwould see it as two requests, and when processing the second request, send back\na response that the proxy does not expect. If the proxy has reused the persistent\nconnection to Puma to send another request for a different client, the second response\nfrom the first client will be sent to the second client.\n\n### Patches\n\nThe problem has been fixed in Puma 3.12.6 and Puma 4.3.5.",
"cvss_v2": null,
"cvss_v3": 6.8,
"cve": "2020-11077",
"osvdb": null,
"ghsa": "w64w-qqph-5gxm",
"unaffected_versions": [

],
"patched_versions": [
"~> 3.12.6",
">= 4.3.5"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2020-5247.yml",
"id": "CVE-2020-5247",
"url": "https://github.com/puma/puma/security/advisories/GHSA-84j7-475p-hp8v",
"title": "HTTP Response Splitting vulnerability in puma",
"date": "2020-02-27",
"description": "If an application using Puma allows untrusted input in a response header,\nan attacker can use newline characters (i.e. CR, LF) to end the header and\ninject malicious content, such as additional headers or an entirely new\nresponse body. This vulnerability is known as HTTP Response Splitting.\n\nWhile not an attack in itself, response splitting is a vector for several\nother attacks, such as cross-site scripting (XSS).",
"cvss_v2": null,
"cvss_v3": 6.5,
"cve": "2020-5247",
"osvdb": null,
"ghsa": "84j7-475p-hp8v",
"unaffected_versions": [

],
"patched_versions": [
"~> 3.12.4",
">= 4.3.3"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2020-5249.yml",
"id": "CVE-2020-5249",
"url": "https://github.com/puma/puma/security/advisories/GHSA-33vf-4xgg-9r58",
"title": "HTTP Response Splitting (Early Hints) in Puma",
"date": "2020-03-03",
"description": "### Impact\nIf an application using Puma allows untrusted input in an early-hints header,\nan attacker can use a carriage return character to end the header and inject\nmalicious content, such as additional headers or an entirely new response body.\nThis vulnerability is known as [HTTP Response\nSplitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)\n\nWhile not an attack in itself, response splitting is a vector for several other\nattacks, such as cross-site scripting (XSS).\n\nThis is related to [CVE-2020-5247](https://github.com/puma/puma/security/advisories/GHSA-84j7-475p-hp8v),\nwhich fixed this vulnerability but only for regular responses.\n\n### Patches\nThis has been fixed in 4.3.3 and 3.12.4.\n\n### Workarounds\nUsers can not allow untrusted/user input in the Early Hints response header.",
"cvss_v2": null,
"cvss_v3": 6.5,
"cve": "2020-5249",
"osvdb": null,
"ghsa": "33vf-4xgg-9r58",
"unaffected_versions": [

],
"patched_versions": [
"~> 3.12.4",
">= 4.3.3"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2021-29509.yml",
"id": "CVE-2021-29509",
"url": "https://github.com/puma/puma/security/advisories/GHSA-q28m-8xjw-8vr5",
"title": "Keepalive Connections Causing Denial Of Service in puma",
"date": "2021-05-11",
"description": "### Impact\n\nThe fix for CVE-2019-16770 was incomplete. The original fix only protected\nexisting connections that had already been accepted from having their\nrequests starved by greedy persistent-connections saturating all threads in\nthe same process. However, new connections may still be starved by greedy\npersistent-connections saturating all threads in all processes in the\ncluster.\n\nA puma server which received more concurrent keep-alive connections than the\nserver had threads in its threadpool would service only a subset of\nconnections, denying service to the unserved connections.\n\n### Patches\n\nThis problem has been fixed in puma 4.3.8 and 5.3.1.\n\n### Workarounds\n\nSetting queue_requests false also fixes the issue. This is not advised when\nusing puma without a reverse proxy, such as nginx or apache, because you will\nopen yourself to slow client attacks (e.g. [slowloris][1]).\n\nThe fix is very small. [A git patch is available here][2] for those using\n[unsupported versions][3] of Puma.\n\n[1]: https://en.wikipedia.org/wiki/Slowloris_(computer_security)\n[2]: https://gist.github.com/nateberkopec/4b3ea5676c0d70cbb37c82d54be25837\n[3]: https://github.com/puma/puma/security/policy#supported-versions",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2021-29509",
"osvdb": null,
"ghsa": "q28m-8xjw-8vr5",
"unaffected_versions": [

],
"patched_versions": [
"~> 4.3.8",
">= 5.3.1"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2021-41136.yml",
"id": "CVE-2021-41136",
"url": "https://github.com/puma/puma/security/advisories/GHSA-48w2-rm65-62xx",
"title": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') in puma",
"date": "2021-10-12",
"description": "### Impact\n\nPrior to 'puma' version 5.5.0, using 'puma' with a proxy which forwards LF characters as line endings could allow HTTP request smuggling. A client could smuggle a request through a proxy, causing the proxy to send a response back to another unknown client.\n\nThis behavior (forwarding LF characters as line endings) is very uncommon amongst proxy servers, so we have graded the impact here as \"low\". Puma is only aware of a single proxy server which has this behavior.\n\nIf the proxy uses persistent connections and the client adds another request in via HTTP pipelining, the proxy may mistake it as the first request's body. Puma, however, would see it as two requests, and when processing the second request, send back a response that the proxy does not expect. If the proxy has reused the persistent connection to Puma to send another request for a different client, the second response from the first client will be sent to the second client.\n\n### Patches\n\nThis vulnerability was patched in Puma 5.5.1 and 4.3.9.\n\n### Workarounds\n\nThis vulnerability only affects Puma installations without any proxy in front.\n\nUse a proxy which does not forward LF characters as line endings.\n\nProxies which do not forward LF characters as line endings:\n\n* Nginx\n* Apache (>2.4.25)\n* Haproxy\n* Caddy\n* Traefik\n\n### Possible Breakage\n\nIf you are [dealing with legacy clients that want to send 'LF' as a line ending](https://stackoverflow.com/questions/43574428/have-apache-accept-lf-vs-crlf-in-request-headers) in an HTTP header, this will cause those clients to receive a '400' error.\n\n### References\n\n* [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)\n",
"cvss_v2": null,
"cvss_v3": 3.7,
"cve": "2021-41136",
"osvdb": null,
"ghsa": "48w2-rm65-62xx",
"unaffected_versions": [

],
"patched_versions": [
"~> 4.3.9",
">= 5.5.1"
],
"criticality": "low"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "puma",
"version": "3.12.1"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/puma/CVE-2022-23634.yml",
"id": "CVE-2022-23634",
"url": "https://github.com/puma/puma/security/advisories/GHSA-rmj8-8hhh-gv5h",
"title": "Information Exposure with Puma when used with Rails",
"date": "2022-02-11",
"description": "### Impact\n\nPrior to 'puma' version '5.6.2', 'puma' may not always call\n'close' on the response body. Rails, prior to version '7.0.2.2', depended on the\nresponse body being closed in order for its 'CurrentAttributes' implementation to\nwork correctly.\n\nFrom Rails:\n\n> Under certain circumstances response bodies will not be closed, for example\n> a bug in a webserver[1] or a bug in a Rack middleware. In the event a\n> response is not notified of a close, ActionDispatch::Executor will not know\n> to reset thread local state for the next request. This can lead to data\n> being leaked to subsequent requests, especially when interacting with\n> ActiveSupport::CurrentAttributes.\n\nThe combination of these two behaviors (Puma not closing the body + Rails'\nExecutor implementation) causes information leakage.\n\n### Patches\n\nThis problem is fixed in Puma versions 5.6.2 and 4.3.11.\n\nThis problem is fixed in Rails versions 7.02.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2.\n\nSee: https://github.com/advisories/GHSA-wh98-p28r-vrc9\nfor details about the rails vulnerability\n\nUpgrading to a patched Rails _or_ Puma version fixes the vulnerability.\n\n### Workarounds\n\nUpgrade to Rails versions 7.0.2.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2.\n\nThe [Rails CVE](https://groups.google.com/g/ruby-security-ann/c/FkTM-_7zSNA/m/K2RiMJBlBAAJ?utm_medium=email&utm_source=footer&pli=1)\nincludes a middleware that can be used instead.\n",
"cvss_v2": null,
"cvss_v3": 8.0,
"cve": "2022-23634",
"osvdb": null,
"ghsa": "rmj8-8hhh-gv5h",
"unaffected_versions": [

],
"patched_versions": [
"~> 4.3.11",
">= 5.6.2"
],
"criticality": "high"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "rack",
"version": "2.0.7"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/rack/CVE-2019-16782.yml",
"id": "CVE-2019-16782",
"url": "https://github.com/rack/rack/security/advisories/GHSA-hrqr-hxpp-chr3",
"title": "Possible information leak / session hijack vulnerability",
"date": "2019-12-18",
"description": "There's a possible information leak / session hijack vulnerability in Rack.\n\nAttackers may be able to find and hijack sessions by using timing attacks\ntargeting the session id. Session ids are usually stored and indexed in a\ndatabase that uses some kind of scheme for speeding up lookups of that\nsession id. By carefully measuring the amount of time it takes to look up\na session, an attacker may be able to find a valid session id and hijack\nthe session.\n\nThe session id itself may be generated randomly, but the way the session is\nindexed by the backing store does not use a secure comparison.\n\nImpact:\n\nThe session id stored in a cookie is the same id that is used when querying\nthe backing session storage engine.  Most storage mechanisms (for example a\ndatabase) use some sort of indexing in order to speed up the lookup of that\nid.  By carefully timing requests and session lookup failures, an attacker\nmay be able to perform a timing attack to determine an existing session id\nand hijack that session.",
"cvss_v2": null,
"cvss_v3": 6.3,
"cve": "2019-16782",
"osvdb": null,
"ghsa": "hrqr-hxpp-chr3",
"unaffected_versions": [

],
"patched_versions": [
"~> 1.6.12",
">= 2.0.8"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "rack",
"version": "2.0.7"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/rack/CVE-2020-8161.yml",
"id": "CVE-2020-8161",
"url": "https://groups.google.com/forum/#!topic/ruby-security-ann/T4ZIsfRf2eA",
"title": "Directory traversal in Rack::Directory app bundled with Rack",
"date": "2020-05-12",
"description": "There was a possible directory traversal vulnerability in the Rack::Directory app\nthat is bundled with Rack.\n\nVersions Affected:  rack < 2.2.0\nNot affected:       Applications that do not use Rack::Directory.\nFixed Versions:     2.1.3, >= 2.2.0\n\nImpact\n------\n\nIf certain directories exist in a director that is managed by\n'Rack::Directory', an attacker could, using this vulnerability, read the\ncontents of files on the server that were outside of the root specified in the\nRack::Directory initializer.\n\nWorkarounds\n-----------\n\nUntil such time as the patch is applied or their Rack version is upgraded,\nwe recommend that developers do not use Rack::Directory in their\napplications.\n",
"cvss_v2": null,
"cvss_v3": null,
"cve": "2020-8161",
"osvdb": null,
"ghsa": "5f9h-9pjv-v6j7",
"unaffected_versions": [

],
"patched_versions": [
"~> 2.1.3",
">= 2.2.0"
],
"criticality": null
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "rack",
"version": "2.0.7"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/rack/CVE-2020-8184.yml",
"id": "CVE-2020-8184",
"url": "https://groups.google.com/g/rubyonrails-security/c/OWtmozPH9Ak",
"title": "Percent-encoded cookies can be used to overwrite existing prefixed cookie names",
"date": "2020-06-15",
"description": "It is possible to forge a secure or host-only cookie prefix in Rack using\nan arbitrary cookie write by using URL encoding (percent-encoding) on the\nname of the cookie. This could result in an application that is dependent on\nthis prefix to determine if a cookie is safe to process being manipulated\ninto processing an insecure or cross-origin request.\nThis vulnerability has been assigned the CVE identifier CVE-2020-8184.\n\nVersions Affected:  rack < 2.2.3, rack < 2.1.4\nNot affected:       Applications which do not rely on __Host- and __Secure- prefixes to determine if a cookie is safe to process\nFixed Versions:     rack >= 2.2.3, rack >= 2.1.4\n\nImpact\n------\n\nAn attacker may be able to trick a vulnerable application into processing an\ninsecure (non-SSL) or cross-origin request if they can gain the ability to write\narbitrary cookies that are sent to the application.\n\nWorkarounds\n-----------\n\nIf your application is impacted but you cannot upgrade to the released versions or apply\nthe provided patch, this issue can be temporarily addressed by adding the following workaround:\n\n'\nmodule Rack\n  module Utils\n    module_function def parse_cookies_header(header)\n      return {} unless header\n      header.split(/[;] */n).each_with_object({}) do |cookie, cookies|\n        next if cookie.empty?\n        key, value = cookie.split('=', 2)\n        cookies[key] = (unescape(value) rescue value) unless cookies.key?(key)\n      end\n    end\n  end\nend\n'\n",
"cvss_v2": null,
"cvss_v3": null,
"cve": "2020-8184",
"osvdb": null,
"ghsa": "j6w9-fv6q-3q52",
"unaffected_versions": [

],
"patched_versions": [
"~> 2.1.4",
">= 2.2.3"
],
"criticality": null
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "rubyzip",
"version": "1.2.3"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/rubyzip/CVE-2019-16892.yml",
"id": "CVE-2019-16892",
"url": "https://github.com/rubyzip/rubyzip/pull/403",
"title": "Denial of Service in rubyzip (\"zip bombs\")",
"date": "2019-09-12",
"description": "In Rubyzip before 1.3.0, a crafted ZIP file can bypass application\nchecks on ZIP entry sizes because data about the uncompressed size\ncan be spoofed. This allows attackers to cause a denial of service\n(disk consumption).\n",
"cvss_v2": null,
"cvss_v3": 5.5,
"cve": "2019-16892",
"osvdb": null,
"ghsa": "5m2v-hc64-56h6",
"unaffected_versions": [

],
"patched_versions": [
">= 1.3.0"
],
"criticality": "medium"
}
},
{
"type": "unpatched_gem",
"gem": {
"name": "websocket-extensions",
"version": "0.1.4"
},
"advisory": {
"path": "/root/.local/share/ruby-advisory-db/gems/websocket-extensions/CVE-2020-7663.yml",
"id": "CVE-2020-7663",
"url": "https://github.com/faye/websocket-extensions-ruby/security/advisories/GHSA-g6wq-qcwm-j5g2",
"title": "Regular Expression Denial of Service in websocket-extensions (RubyGem)",
"date": "2020-06-05",
"description": "### Impact\n\nThe ReDoS flaw allows an attacker to exhaust the server's capacity to process\nincoming requests by sending a WebSocket handshake request containing a header\nof the following form:\n\n    Sec-WebSocket-Extensions: a; b=\"\\c\\c\\c\\c\\c\\c\\c\\c\\c\\c ...\n\nThat is, a header containing an unclosed string parameter value whose content is\na repeating two-byte sequence of a backslash and some other character. The\nparser takes exponential time to reject this header as invalid, and this will\nblock the processing of any other work on the same thread. Thus if you are\nrunning a single-threaded server, such a request can render your service\ncompletely unavailable.\n\n### Workarounds\n\nThere are no known work-arounds other than disabling any public-facing WebSocket functionality you are operating.",
"cvss_v2": null,
"cvss_v3": 7.5,
"cve": "2020-7663",
"osvdb": null,
"ghsa": "g6wq-qcwm-j5g2",
"unaffected_versions": [

],
"patched_versions": [
">= 0.1.5"
],
"criticality": "high"
}
}
]
}

`
