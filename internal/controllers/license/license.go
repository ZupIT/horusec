package license

import (
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/internal/services/docker/client"
	"github.com/google/uuid"
	"os"
)

type License string

const (
	MIT    License = "MIT"
	Apache License = "Apache 2.0"
	NewBSD License = "New BSD"

	image = "xablue"
	cmd   = "license_finder report --format json --quiet > result.json \n cat result.json"
)

type Result struct {
	Dependencies []*Dependency
}

type Dependency struct {
	Name     string
	Version  string
	Licenses []License
}

func (d *Dependency) IsInvalidDependency(permittedLicenses []string) bool {
	for _, permittedLicense := range permittedLicenses {
		for _, depLicense := range d.Licenses {
			if License(permittedLicense) != depLicense {
				return true
			}
		}
	}

	return false
}

type Service struct {
	config                 *config.Config
	docker                 docker.Docker
	invalidDependencies    []*Dependency
	alreadyMarkedAsInvalid map[string]bool
}

func NewLicenseService(cfg *config.Config) *Service {
	return &Service{
		config: cfg,
		docker: docker.New(dockerClient.NewDockerClient(), cfg, uuid.New(), true),
	}
}

func (s *Service) StartLicenseAnalysis() error {
	if err := s.docker.PullImage(image); err != nil {
		return err
	}

	analysisData := &dockerEntities.AnalysisData{
		DefaultImage: image,
		CMD:          cmd,
	}

	output, err := s.docker.CreateLanguageAnalysisContainer(analysisData)
	if err != nil {
		return err
	}

	result := &Result{}
	if err := json.Unmarshal([]byte(output), result); err != nil {
		return err
	}

	s.checkForInvalidDependencies(result)
	s.printInvalidDependencies()
	return nil
}

func (s *Service) checkForInvalidDependencies(result *Result) {
	if len(s.config.PermittedLicenses) == 0 {
		s.invalidDependencies = result.Dependencies
	}

	for _, dependency := range result.Dependencies {
		if s.isNotAlreadyValidated(dependency) && dependency.IsInvalidDependency(s.config.PermittedLicenses) {
			s.invalidDependencies = append(s.invalidDependencies, dependency)
		}
	}
}

func (s *Service) isNotAlreadyValidated(dependency *Dependency) bool {
	if _, ok := s.alreadyMarkedAsInvalid[dependency.Name+dependency.Version]; ok {
		return false
	}

	return true
}

func (s *Service) printInvalidDependencies() {
	if len(s.invalidDependencies) != 0 {
		s.logSeparator()
		logger.LogPrint("-> LIST OF INVALID DEPENDENCIES")
	} else {
		s.logSeparator()
		logger.LogPrint("-> NO INVALID DEPENDENCIES WERE FOUND")
	}

	for _, dep := range s.invalidDependencies {
		s.logSeparator()
		logger.LogPrint(fmt.Sprintf("DEPENDENCY: %s, VERSION: %s, LICENSES: %s", dep.Name, dep.Version, dep.Licenses))
	}

	s.logSeparator()

	if len(s.invalidDependencies) != 0 {
		os.Exit(1)
	}
}

func (s *Service) logSeparator() {
	print("=========================================================================================================\n")
}
