package config

import (
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) GetConfigFilePath() string {
	args := m.MethodCalled("GetConfigFilePath")
	return args.Get(0).(string)
}
func (m *Mock) SetConfigFilePath(configFilePath string) {
	_ = m.MethodCalled("SetConfigFilePath")
}
func (m *Mock) GetHorusecAPIUri() string {
	args := m.MethodCalled("GetHorusecAPIUri")
	return args.Get(0).(string)
}
func (m *Mock) SetHorusecAPIURI(horusecAPIURI string) {
	_ = m.MethodCalled("SetHorusecAPIURI")
}
func (m *Mock) GetTimeoutInSecondsRequest() int64 {
	args := m.MethodCalled("GetTimeoutInSecondsRequest")
	return args.Get(0).(int64)
}
func (m *Mock) SetTimeoutInSecondsRequest(timeoutInSecondsRequest int64) {
	_ = m.MethodCalled("SetTimeoutInSecondsRequest")
}
func (m *Mock) GetTimeoutInSecondsAnalysis() int64 {
	args := m.MethodCalled("GetTimeoutInSecondsAnalysis")
	return args.Get(0).(int64)
}
func (m *Mock) SetTimeoutInSecondsAnalysis(timeoutInSecondsAnalysis int64) {
	_ = m.MethodCalled("SetTimeoutInSecondsAnalysis")
}
func (m *Mock) GetMonitorRetryInSeconds() int64 {
	args := m.MethodCalled("GetMonitorRetryInSeconds")
	return args.Get(0).(int64)
}
func (m *Mock) SetMonitorRetryInSeconds(retryInterval int64) {
	_ = m.MethodCalled("SetMonitorRetryInSeconds")
}
func (m *Mock) GetRepositoryAuthorization() string {
	args := m.MethodCalled("GetRepositoryAuthorization")
	return args.Get(0).(string)
}
func (m *Mock) SetRepositoryAuthorization(repositoryAuthorization string) {
	_ = m.MethodCalled("SetRepositoryAuthorization")
}
func (m *Mock) GetPrintOutputType() string {
	args := m.MethodCalled("GetPrintOutputType")
	return args.Get(0).(string)
}
func (m *Mock) SetPrintOutputType(printOutputType string) {
	_ = m.MethodCalled("SetPrintOutputType")
}
func (m *Mock) GetJSONOutputFilePath() string {
	args := m.MethodCalled("GetJSONOutputFilePath")
	return args.Get(0).(string)
}
func (m *Mock) SetJSONOutputFilePath(jsonOutputFilePath string) {
	_ = m.MethodCalled("SetJSONOutputFilePath")
}
func (m *Mock) GetSeveritiesToIgnore() []string {
	args := m.MethodCalled("GetSeveritiesToIgnore")
	return args.Get(0).([]string)
}
func (m *Mock) SetSeveritiesToIgnore(severitiesToIgnore []string) {
	_ = m.MethodCalled("SetSeveritiesToIgnore")
}
func (m *Mock) GetFilesOrPathsToIgnore() []string {
	args := m.MethodCalled("GetFilesOrPathsToIgnore")
	return args.Get(0).([]string)
}
func (m *Mock) SetFilesOrPathsToIgnore(filesOrPaths []string) {
	_ = m.MethodCalled("SetFilesOrPathsToIgnore")
}
func (m *Mock) GetReturnErrorIfFoundVulnerability() bool {
	args := m.MethodCalled("GetReturnErrorIfFoundVulnerability")
	return args.Get(0).(bool)
}
func (m *Mock) SetReturnErrorIfFoundVulnerability(returnError bool) {
	_ = m.MethodCalled("SetReturnErrorIfFoundVulnerability")
}
func (m *Mock) GetProjectPath() string {
	args := m.MethodCalled("GetProjectPath")
	return args.Get(0).(string)
}
func (m *Mock) SetProjectPath(projectPath string) {
	_ = m.MethodCalled("SetProjectPath")
}
func (m *Mock) GetFilterPath() string {
	args := m.MethodCalled("GetFilterPath")
	return args.Get(0).(string)
}
func (m *Mock) SetFilterPath(filterPath string) {
	_ = m.MethodCalled("SetFilterPath")
}
func (m *Mock) GetWorkDir() *workdir.WorkDir {
	args := m.MethodCalled("GetWorkDir")
	return args.Get(0).(*workdir.WorkDir)
}
func (m *Mock) SetWorkDir(toParse interface{}) {
	_ = m.MethodCalled("SetWorkDir")
}
func (m *Mock) GetEnableGitHistoryAnalysis() bool {
	args := m.MethodCalled("GetEnableGitHistoryAnalysis")
	return args.Get(0).(bool)
}
func (m *Mock) SetEnableGitHistoryAnalysis(enableGitHistoryAnalysis bool) {
	_ = m.MethodCalled("SetEnableGitHistoryAnalysis")
}
func (m *Mock) GetCertInsecureSkipVerify() bool {
	args := m.MethodCalled("GetCertInsecureSkipVerify")
	return args.Get(0).(bool)
}
func (m *Mock) SetCertInsecureSkipVerify(certInsecureSkipVerify bool) {
	_ = m.MethodCalled("SetCertInsecureSkipVerify")
}
func (m *Mock) GetCertPath() string {
	args := m.MethodCalled("GetCertPath")
	return args.Get(0).(string)
}
func (m *Mock) SetCertPath(certPath string) {
	_ = m.MethodCalled("SetCertPath")
}
func (m *Mock) GetEnableCommitAuthor() bool {
	args := m.MethodCalled("GetEnableCommitAuthor")
	return args.Get(0).(bool)
}
func (m *Mock) SetEnableCommitAuthor(isEnable bool) {
	_ = m.MethodCalled("SetEnableCommitAuthor")
}
func (m *Mock) GetRepositoryName() string {
	args := m.MethodCalled("GetRepositoryName")
	return args.Get(0).(string)
}
func (m *Mock) SetRepositoryName(repositoryName string) {
	_ = m.MethodCalled("SetRepositoryName")
}
func (m *Mock) GetRiskAcceptHashes() (output []string) {
	args := m.MethodCalled("GetRiskAcceptHashes")
	return args.Get(0).([]string)
}
func (m *Mock) SetRiskAcceptHashes(riskAccept []string) {
	_ = m.MethodCalled("SetRiskAcceptHashes")
}
func (m *Mock) GetFalsePositiveHashes() (output []string) {
	args := m.MethodCalled("GetFalsePositiveHashes")
	return args.Get(0).([]string)
}
func (m *Mock) SetFalsePositiveHashes(falsePositive []string) {
	_ = m.MethodCalled("SetFalsePositiveHashes")
}
func (m *Mock) GetToolsToIgnore() (output []string) {
	args := m.MethodCalled("GetToolsToIgnore")
	return args.Get(0).([]string)
}
func (m *Mock) SetToolsToIgnore(toolsToIgnore []string) {
	_ = m.MethodCalled("SetToolsToIgnore")
}
func (m *Mock) GetHeaders() (headers map[string]string) {
	args := m.MethodCalled("GetHeaders")
	return args.Get(0).(map[string]string)
}
func (m *Mock) SetHeaders(headers interface{}) {
	_ = m.MethodCalled("SetHeaders")
}
func (m *Mock) GetContainerBindProjectPath() string {
	args := m.MethodCalled("GetContainerBindProjectPath")
	return args.Get(0).(string)
}
func (m *Mock) SetContainerBindProjectPath(containerBindProjectPath string) {
	_ = m.MethodCalled("SetContainerBindProjectPath")
}
func (m *Mock) GetIsTimeout() bool {
	args := m.MethodCalled("GetIsTimeout")
	return args.Get(0).(bool)
}
func (m *Mock) SetIsTimeout(isTimeout bool) {
	_ = m.MethodCalled("SetIsTimeout")
}
func (m *Mock) IsEmptyRepositoryAuthorization() bool {
	args := m.MethodCalled("IsEmptyRepositoryAuthorization")
	return args.Get(0).(bool)
}
func (m *Mock) ToBytes(isMarshalIndent bool) (bytes []byte) {
	args := m.MethodCalled("ToBytes")
	return args.Get(0).([]byte)
}
func (m *Mock) NormalizeConfigs() IConfig {
	args := m.MethodCalled("NormalizeConfigs")
	return args.Get(0).(*Config)
}

func (m *Mock) NewConfigsFromCobraAndLoadsFlags(cmd *cobra.Command) IConfig {
	args := m.MethodCalled("NewConfigsFromCobraAndLoadsFlags")
	return args.Get(0).(*Config)
}
func (m *Mock) NewConfigsFromViper() IConfig {
	args := m.MethodCalled("NewConfigsFromViper")
	return args.Get(0).(*Config)
}
func (m *Mock) NewConfigsFromEnvironments() IConfig {
	args := m.MethodCalled("NewConfigsFromEnvironments")
	return args.Get(0).(*Config)
}
