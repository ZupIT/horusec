package start

import (
	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config/dist"
	"github.com/spf13/pflag"
	"os"
	"path/filepath"
)

func startFlags(flags *pflag.FlagSet) {
	wd, err := os.Getwd()
	if err != nil {
		logger.LogWarn("Error to get current working directory: %v", err)
	}

	flags.Int64P(
		"monitor-retry-count", "m",
		15,
		"The number of retries for the monitor.",
	)

	flags.
		StringP(
			"output-format", "o",
			"",
			"The format for the output to be shown. Options are: text (stdout), json, sonarqube",
		)

	flags.
		StringSliceP(
			"ignore-severity", "s",
			[]string{"INFO"},
			"The level of vulnerabilities to ignore in the output. Example: -s=\"LOW, MEDIUM, HIGH\"",
		)

	flags.
		StringP(
			"json-output-file", "O",
			"",
			"If your pass output-format you can configure the output JSON location. Example: -O=\"/tmp/output.json\"",
		)

	flags.
		StringSliceP(
			"ignore", "i",
			[]string{"*tmp*", "**/.vscode/**"},
			"Paths to ignore in the analysis. Example: -i=\"/home/user/project/assets, /home/user/project/deployments\"",
		)

	flags.
		StringP(
			"horusec-url", "u",
			"http://0.0.0.0:8000",
			"The Horusec API address to access the analysis engine",
		)

	flags.
		Int64P(
			"request-timeout", "r",
			300,
			"The timeout threshold for the request to the Horusec API",
		)

	flags.
		Int64P(
			"analysis-timeout", "t",
			600,
			"The timeout threshold for the Horusec CLI wait for the analysis to complete.",
		)

	flags.
		StringP(
			"authorization", "a",
			"",
			"The authorization token for the Horusec API",
		)

	flags.
		StringToString(
			"headers",
			make(map[string]string),
			"The headers dynamic to send on request in Horusec API. Example --headers=\"{\"X-Auth-Service\": \"my-value\"}\"",
		)

	flags.
		BoolP(
			"return-error", "e",
			false,
			"The return-error is the option to check if you can return \"exit(1)\" if found vulnerabilities. Example -e=\"true\"",
		)

	flags.
		StringP(
			"project-path", "p",
			wd,
			"Path to run an analysis in your project",
		)

	flags.
		Bool(
			"enable-git-history",
			false,
			"When this value is \"true\" we will run tool gitleaks and search vulnerability in all git history of the project. Example --enable-git-history=\"true\"",
		)

	flags.
		BoolP(
			"insecure-skip-verify", "S",
			false,
			"Insecure skip verify cert authority. PLEASE, try not to use it. Example -S=\"true\"",
		)

	flags.
		StringP(
			"certificate-path", "C",
			"",
			"Path to certificate of authority. Example -C=\"/example/ca.crt\"",
		)

	flags.
		BoolP(
			"enable-commit-author", "G",
			false,
			"Used to enable or disable search with vulnerability author. Example -G=\"true\"",
		)

	flags.
		StringP(
			"repository-name", "n",
			filepath.Base(wd),
			"Used to send repository name to horus server. Example -n=\"horus\"",
		)

	flags.
		StringSliceP(
			"false-positive", "F",
			make([]string, 0),
			"Used to ignore a vulnerability by hash and setting it to be of the false positive type. Example -F=\"hash1, hash2\"",
		)

	flags.
		StringSliceP(
			"risk-accept", "R",
			make([]string, 0),
			"Used to ignore a vulnerability by hash and setting it to be of the risk accept type. Example -R=\"hash3, hash4\"",
		)

	flags.
		StringP(
			"container-bind-project-path", "P",
			"",
			"Used to pass project path in host when running horusec cli inside a container.",
		)

	flags.
		StringP(
			"custom-rules-path", "c",
			"",
			"Used to pass the path to the horusec custom rules file. Example: -c=\"./horusec/horusec-custom-rules.json\".",
		)

	flags.
		BoolP(
			"information-severity", "I",
			false,
			"Used to enable or disable information severity vulnerabilities, information vulnerabilities can contain a lot of false positives. Example: -I=\"true\"",
		)

	flags.
		StringSlice(
			"show-vulnerabilities-types",
			[]string{vulnerability.Vulnerability.ToString()},
			"Used to show in the output vulnerabilities of types: Vulnerability, Risk Accepted, False Positive, Corrected. Example --show-vulnerabilities-types=\"Vulnerability, Risk Accepted\"",
		)

	flags.
		BoolP(
			"enable-owasp-dependency-check", "w",
			false,
			"Enable owasp dependency check. Example -w=\"true\". Default: false",
		)

	flags.
		BoolP(
			"enable-shellcheck", "j",
			false,
			"Enable shellcheck. Example -h=\"true\". Default: false",
		)

	if !dist.IsStandAlone() {
		flags.
			BoolP(
				"disable-docker", "D",
				dist.IsStandAlone(),
				"Used to run horusec without docker if enabled it will only run the following tools: horusec-csharp, horusec-kotlin, horusec-java, horusec-kubernetes, horusec-leaks, horusec-nodejs, horusec-dart, horusec-nginx. Example: -D=\"true\"",
			)
	}

}

type NewConfig struct {
	HorusecCliCertInsecureSkipVerify   bool   `json:"horusecCliCertInsecureSkipVerify"`
	HorusecCliCertPath                 string `json:"horusecCliCertPath"`
	HorusecCliContainerBindProjectPath string `json:"horusecCliContainerBindProjectPath"`
	HorusecCliCustomImages             struct {
		C          string `json:"c"`
		Csharp     string `json:"csharp"`
		Elixir     string `json:"elixir"`
		Generic    string `json:"generic"`
		Go         string `json:"go"`
		Hcl        string `json:"hcl"`
		Javascript string `json:"javascript"`
		Leaks      string `json:"leaks"`
		Php        string `json:"php"`
		Python     string `json:"python"`
		Ruby       string `json:"ruby"`
		Shell      string `json:"shell"`
	} `json:"horusecCliCustomImages"`
	HorusecCliCustomRulesPath           string        `json:"horusecCliCustomRulesPath"`
	HorusecCliDisableDocker             bool          `json:"horusecCliDisableDocker"`
	HorusecCliEnableCommitAuthor        bool          `json:"horusecCliEnableCommitAuthor"`
	HorusecCliEnableGitHistoryAnalysis  bool          `json:"horusecCliEnableGitHistoryAnalysis"`
	HorusecCliEnableInformationSeverity bool          `json:"horusecCliEnableInformationSeverity"`
	HorusecCliFalsePositiveHashes       []interface{} `json:"horusecCliFalsePositiveHashes"`
	HorusecCliFilesOrPathsToIgnore      []string      `json:"horusecCliFilesOrPathsToIgnore"`
	HorusecCliHeaders                   struct {
	} `json:"horusecCliHeaders"`
	HorusecCliHorusecAPIURI                   string        `json:"horusecCliHorusecApiUri"`
	HorusecCliJSONOutputFilepath              string        `json:"horusecCliJsonOutputFilepath"`
	HorusecCliMonitorRetryInSeconds           int           `json:"horusecCliMonitorRetryInSeconds"`
	HorusecCliPrintOutputType                 string        `json:"horusecCliPrintOutputType"`
	HorusecCliProjectPath                     string        `json:"horusecCliProjectPath"`
	HorusecCliRepositoryAuthorization         string        `json:"horusecCliRepositoryAuthorization"`
	HorusecCliRepositoryName                  string        `json:"horusecCliRepositoryName"`
	HorusecCliReturnErrorIfFoundVulnerability bool          `json:"horusecCliReturnErrorIfFoundVulnerability"`
	HorusecCliRiskAcceptHashes                []interface{} `json:"horusecCliRiskAcceptHashes"`
	HorusecCliSeveritiesToIgnore              []interface{} `json:"horusecCliSeveritiesToIgnore"`
	HorusecCliShowVulnerabilitiesTypes        []interface{} `json:"horusecCliShowVulnerabilitiesTypes"`
	HorusecCliTimeoutInSecondsAnalysis        int           `json:"horusecCliTimeoutInSecondsAnalysis"`
	HorusecCliTimeoutInSecondsRequest         int           `json:"horusecCliTimeoutInSecondsRequest"`
	HorusecCliToolsConfig                     struct {
		Bandit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Bandit"`
		Brakeman struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Brakeman"`
		BundlerAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"BundlerAudit"`
		Checkov struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Checkov"`
		Flawfinder struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Flawfinder"`
		GitLeaks struct {
			Istoignore bool `json:"istoignore"`
		} `json:"GitLeaks"`
		GoSec struct {
			Istoignore bool `json:"istoignore"`
		} `json:"GoSec"`
		HorusecEngine struct {
			Istoignore bool `json:"istoignore"`
		} `json:"HorusecEngine"`
		MixAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"MixAudit"`
		NpmAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"NpmAudit"`
		PhpCS struct {
			Istoignore bool `json:"istoignore"`
		} `json:"PhpCS"`
		Safety struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Safety"`
		SecurityCodeScan struct {
			Istoignore bool `json:"istoignore"`
		} `json:"SecurityCodeScan"`
		Semgrep struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Semgrep"`
		ShellCheck struct {
			Istoignore bool `json:"istoignore"`
		} `json:"ShellCheck"`
		Sobelow struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Sobelow"`
		TfSec struct {
			Istoignore bool `json:"istoignore"`
		} `json:"TfSec"`
		YarnAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"YarnAudit"`
	} `json:"horusecCliToolsConfig"`
	HorusecCliWorkDir struct {
		Go         []interface{} `json:"go"`
		Csharp     []interface{} `json:"csharp"`
		Ruby       []interface{} `json:"ruby"`
		Python     []interface{} `json:"python"`
		Java       []interface{} `json:"java"`
		Kotlin     []interface{} `json:"kotlin"`
		JavaScript []interface{} `json:"javaScript"`
		Leaks      []interface{} `json:"leaks"`
		Hcl        []interface{} `json:"hcl"`
		Php        []interface{} `json:"php"`
		C          []interface{} `json:"c"`
		Yaml       []interface{} `json:"yaml"`
		Generic    []interface{} `json:"generic"`
		Elixir     []interface{} `json:"elixir"`
		Shell      []interface{} `json:"shell"`
		Dart       []interface{} `json:"dart"`
		Nginx      []interface{} `json:"nginx"`
	} `json:"horusecCliWorkDir"`
}