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

package errors

import "errors"

// Occurs when o git is not installed in O.S

var ErrGitNotInstalled = errors.New("{HORUSEC_CLI} Error Git not found. Please check and try again")

// Occurs when o git is lower version required

var ErrGitLowerVersion = errors.New("{HORUSEC_CLI} Error Git version is lower of 2.01. Please check and try again")

// Occurs when o docker is not installed in O.S

var ErrDockerNotInstalled = errors.New("{HORUSEC_CLI} Error Docker not found. Please check and try again")

// Occurs when CsProj not found in dotnet project

var ErrCsProjNotFound = errors.New("{HORUSEC_CLI} Error project csproj not found. Please use workdir flag or try again")

// Occurs when not found rails project

var ErrNotFoundRailsProject = errors.New("{HORUSEC_CLI} Error not found rails project syntax")
