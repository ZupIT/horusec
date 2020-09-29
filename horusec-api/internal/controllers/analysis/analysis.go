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

package analysis

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryAnalysis "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/analysis"
	repositoryCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/company"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	apiEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	horusecEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	analysisUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/google/uuid"
)

type IController interface {
	SaveAnalysis(analysisData *apiEntities.AnalysisData) (uuid.UUID, error)
	GetAnalysis(analysisID uuid.UUID) (*horusecEntities.Analysis, error)
}

type Controller struct {
	postgresWrite    relational.InterfaceWrite
	useCasesAnalysis analysisUseCases.Interface
	repoCompany      repositoryCompany.ICompanyRepository
	repoRepository   repository.IRepository
	repoAnalysis     repositoryAnalysis.IAnalysisRepository
}

func NewAnalysisController(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) IController {
	return &Controller{
		postgresWrite:    postgresWrite,
		useCasesAnalysis: analysisUseCases.NewAnalysisUseCases(),
		repoRepository:   repository.NewRepository(postgresRead, postgresWrite),
		repoCompany:      repositoryCompany.NewCompanyRepository(postgresRead, postgresWrite),
		repoAnalysis:     repositoryAnalysis.NewAnalysisRepository(postgresRead, postgresWrite),
	}
}

func (c *Controller) SaveAnalysis(analysisData *apiEntities.AnalysisData) (uuid.UUID, error) {
	company, err := c.repoCompany.GetByID(analysisData.Analysis.CompanyID)
	if err != nil {
		return uuid.Nil, err
	}
	repo, err := c.getRepository(analysisData)
	if err != nil {
		return uuid.Nil, err
	}
	c.setDefaultContentToCreate(analysisData.Analysis, company.Name, repo)
	return c.createAnalyzeAndVulnerabilities(analysisData.Analysis)
}

func (c *Controller) getRepository(analysisData *apiEntities.AnalysisData) (
	repo *accountEntities.Repository, err error) {
	if analysisData.RepositoryName != "" && analysisData.Analysis.RepositoryID == uuid.Nil {
		repo, err = c.repoRepository.GetByName(analysisData.Analysis.CompanyID, analysisData.RepositoryName)
		return repo, err
	}

	return c.repoRepository.Get(analysisData.Analysis.RepositoryID)
}

func (c *Controller) setDefaultContentToCreate(
	analysis *horusecEntities.Analysis, companyName string, repo *accountEntities.Repository) {
	analysis.GenerateID()
	analysis.SetCompanyName(companyName)
	analysis.SetRepositoryName(repo.Name)
	analysis.SetRepositoryID(repo.RepositoryID)
	analysis.SetAnalysisIDAndNewIDInVulnerabilities()
}

func (c *Controller) createAnalyzeAndVulnerabilities(analysis *horusecEntities.Analysis) (uuid.UUID, error) {
	conn := c.postgresWrite.StartTransaction()
	if err := c.createAnalyze(analysis, conn); err != nil {
		logger.LogError(
			"{HORUSEC_API} Error in rollback transaction analysis",
			conn.RollbackTransaction().GetError(),
		)
		return uuid.Nil, err
	}
	return analysis.GetID(), conn.CommitTransaction().GetError()
}

func (c *Controller) GetAnalysis(analysisID uuid.UUID) (*horusecEntities.Analysis, error) {
	return c.repoAnalysis.GetByID(analysisID)
}

func (c *Controller) createAnalyze(analysis *horusecEntities.Analysis, conn relational.InterfaceWrite) error {
	return c.repoAnalysis.Create(analysis, conn)
}
