package license

import (
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/internal/services/docker/client"
	"github.com/briandowns/spinner"
	"github.com/google/uuid"
	"os"
	"time"
)

type License string

const (
	MIT    License = "MIT"
	Apache License = "Apache 2.0"
	NewBSD License = "New BSD"

	image = "license_finder_poc"
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

func (l License) ContainsLicense(permittedLicenses []string) bool {
	for _, permittedLicense := range permittedLicenses {
		if string(l) == permittedLicense {
			return true
		}
	}

	return false
}

func (d *Dependency) IsInvalidDependency(permittedLicenses []string) bool {
	if len(d.Licenses) == 1 {
		if d.Licenses[0].ContainsLicense(permittedLicenses) {
			return false
		}

		return true
	}

	for _, depLicense := range d.Licenses {
		if depLicense.ContainsLicense(permittedLicenses) {
			continue
		} else {
			return true
		}
	}

	return false
}

const LoadingDelay = 200 * time.Millisecond

type Service struct {
	config              *config.Config
	docker              docker.Docker
	invalidDependencies []*Dependency
	loading             *spinner.Spinner
}

func newScanLoading() *spinner.Spinner {
	loading := spinner.New(spinner.CharSets[11], LoadingDelay)
	loading.Suffix = messages.MsgInfoAnalysisLoading

	return loading
}

func NewLicenseService(cfg *config.Config) *Service {
	return &Service{
		config:  cfg,
		docker:  docker.New(dockerClient.NewDockerClient(), cfg, uuid.New(), true),
		loading: newScanLoading(),
	}
}

func (s *Service) StartLicenseAnalysis() error {
	print("\n")
	s.loading.Start()

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

	s.loading.Stop()

	s.printInvalidDependencies()
	return nil
}

func (s *Service) checkForInvalidDependencies(result *Result) {
	if len(s.config.PermittedLicenses) == 0 {
		s.invalidDependencies = result.Dependencies
	}

	for _, dependency := range result.Dependencies {
		if dependency.IsInvalidDependency(s.config.PermittedLicenses) {
			s.invalidDependencies = append(s.invalidDependencies, dependency)
		}
	}
}

func (s *Service) printInvalidDependencies() {
	if len(s.invalidDependencies) != 0 {
		s.logSeparator()
		logger.LogPrint("LIST OF INVALID DEPENDENCIES")
	} else {
		s.logSeparator()
		logger.LogPrint("NO INVALID DEPENDENCIES WERE FOUND")
	}

	for _, dep := range s.invalidDependencies {
		s.logSeparator()
		logger.LogPrint(fmt.Sprintf("DEPENDENCY: %s", dep.Name))
		logger.LogPrint(fmt.Sprintf("VERSION: %s", dep.Version))
		logger.LogPrint(fmt.Sprintf("LICENSES: %s", dep.Licenses))
	}

	s.logSeparator()

	if len(s.invalidDependencies) != 0 {
		os.Exit(1)
	}
}

func (s *Service) logSeparator() {
	print("\n=========================================================================================================\n\n")
}
