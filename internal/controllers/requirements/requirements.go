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

package requirements

import (
	"errors"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/controllers/requirements/docker"
	"github.com/ZupIT/horusec/internal/controllers/requirements/git"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

var ErrRequirements = errors.New("check the requirements for run and try again")

type IRequirements interface {
	ValidateDocker()
	ValidateGit()
}

type Requirements struct {
	gitRequirements    *git.RequirementGit
	dockerRequirements *docker.RequirementDocker
}

func NewRequirements() IRequirements {
	return &Requirements{
		gitRequirements:    git.NewRequirementGit(),
		dockerRequirements: docker.NewRequirementDocker(),
	}
}

func (r *Requirements) ValidateDocker() {
	err := r.dockerRequirements.ValidateDocker()
	if err != nil {
		logger.LogPanicWithLevel(messages.MsgPanicDockerRequirementsToRunHorusec, ErrRequirements)
	}
}

func (r *Requirements) ValidateGit() {
	err := r.gitRequirements.ValidateGit()
	if err != nil {
		logger.LogPanicWithLevel(messages.MsgPanicGitRequirementsToRunHorusec, ErrRequirements)
	}
}
