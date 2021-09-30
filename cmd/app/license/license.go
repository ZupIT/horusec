package license

import (
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/controllers/license"
	"github.com/spf13/cobra"
	"os"
)

type License struct {
	configs        *config.Config
	licenseService *license.Service
}

func NewLicenseCommand(cfg *config.Config) *License {
	return &License{
		configs:        cfg,
		licenseService: license.NewLicenseService(cfg),
	}
}

func (l *License) CreateLicenseCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "license",
		Short:   "Check the licenses of the project dependencies",
		Long:    "This command will execute License Finder tool, it will check the licenses of the project dependencies and may take a long time",
		Example: "horusec license",
		PreRunE: l.configs.PreRun,
		RunE:    l.runE,
	}

	command.PersistentFlags().
		StringVarP(
			&l.configs.ProjectPath,
			"project-path", "p",
			l.configs.ProjectPath,
			"Path to check licenses",
		)

	return command
}

func (l *License) runE(cmd *cobra.Command, _ []string) error {
	if _, err := os.Stat(l.configs.ProjectPath); os.IsNotExist(err) {
		return err
	}

	return l.licenseService.StartLicenseAnalysis()
}
