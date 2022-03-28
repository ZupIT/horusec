// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

//go:build mage

// This is horusec private mage functions, check https://github.com/ZupIT/horusec-devkit/tree/main/pkg/utils/mageutils
// for basics functions.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	// mage:import
	_ "github.com/ZupIT/horusec-devkit/pkg/utils/mageutils"
	"github.com/google/go-github/v40/github"
	"github.com/magefile/mage/sh"
	"golang.org/x/oauth2"
)

// env vars
const (
	envRepositoryOrg  = "HORUSEC_REPOSITORY_ORG"
	envRepositoryName = "HORUSEC_REPOSITORY_NAME"
	envGithubToken    = "GITHUB_TOKEN"
)

// GetCurrentDate execute "echo", `::set-output name=date::$(date "+%a %b %d %H:%M:%S %Y")`
func GetCurrentDate() error {
	date, err := sh.Output("date", "+%a %b %d %H:%M:%S %Y")
	if err != nil {
		return err
	}

	return sh.RunV("echo", fmt.Sprintf("::set-output name=date::%s", date))
}

// GetReleaseInfo get the latest launched release tag, including beta, rc and latest. Then print the outputs
// 'lastLaunchedRelease' which is the found tag, and 'actualReleaseBranchName' containing the release branch name
// related to the tag.
func GetReleaseInfo() error {
	tags, resp, err := newGithubClient().Repositories.ListTags(
		context.Background(),
		os.Getenv(envRepositoryOrg),
		os.Getenv(envRepositoryName),
		&github.ListOptions{Page: 1, PerPage: 1},
	)

	if github.CheckResponse(resp.Response) != nil {
		return err
	}

	printOutputs(*tags[0].Name)

	return nil
}

// newGithubClient creates a new github.Client with the GitHub auth token
func newGithubClient() *github.Client {
	token := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv(envGithubToken)},
	)

	return github.NewClient(oauth2.NewClient(context.Background(), token))
}

// printOutputs print the outputs 'lastLaunchedRelease' which is the found tag and 'actualReleaseBranchName'
// containing the release branch name related to the tag.
func printOutputs(version string) {
	fmt.Printf("::set-output name=lastLaunchedRelease::%s\n", version)
	fmt.Printf("::set-output name=actualReleaseBranchName::%s\n", getReleaseBranch(version))
}

// getReleaseBranch splits the version raw string into major and minor version. With this info the release branch
// name is mounted.
func getReleaseBranch(version string) string {
	splittedVersion := strings.Split(removePrefixes(version), ".")
	major := splittedVersion[0]
	minor := splittedVersion[1]

	return fmt.Sprintf("release/v%s.%s", major, minor)
}

// removePrefixes remove all the prefixes from the version, including '-rc', '-beta', 'v'.
func removePrefixes(version string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(version, "-rc", ""),
		"-beta", ""), "v", "")
}
