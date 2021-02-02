package commands

import (
	"fmt"
	"github.com/ZupIT/horusec/deployments/semver/internal/entities"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

type FilterAndUpCommand struct {
	upCommand IUpCommand
	cmd *cobra.Command
	filterPaths []string
	pathsChangedInLastCommit []string
}

func NewFilterAndUpCommand(upCommand IUpCommand) ICommand {
	cmd := &FilterAndUpCommand{
		upCommand: upCommand,
	}
	cmd.init()
	return cmd
}

func (f *FilterAndUpCommand) init() {
	f.cmd = &cobra.Command{
		Use:       "filter-and-up",
		Short:     "Filter in path and update version",
		Long:      "Filter in path using git command and check if is necessary update versioning file",
		Example:   "semver filter-and-up alpha --filter-paths=\"horusec-auth, development-kit/pkg/engines\"",
		RunE:      f.execute,
		Args:      cobra.ExactValidArgs(1),
		ValidArgs: []string{"alpha", "beta", "rc", "release", "minor", "major"},
	}
	_ = f.cmd.PersistentFlags().
		StringSliceP("paths", "p", f.filterPaths,"Used to find if path has been updated" +
			" in between current commit and last commit. Example --paths=\"path1, path2/subpath\"")
}

func (f *FilterAndUpCommand) Cmd() *cobra.Command {
	return f.cmd
}

func (f *FilterAndUpCommand) execute(cmd *cobra.Command, args []string) error {
	if len(f.filterPaths) == 0 {
		return fmt.Errorf("flag \"paths\" is required 1 path")
	}
	if err := f.validateFilterPaths(); err != nil {
		return err
	}
	if err := f.setPathsChangedInLastCommit(); err != nil {
		return err
	}
	return f.updateVersion(args[0])
}

func (f *FilterAndUpCommand) updateVersion(updateType string) error {
	version, err := entities.NewVersion(viper.GetString("release"))
	if err != nil {
		return fmt.Errorf("failed to load release version: %v", err)
	}

	return f.upCommand.Handle(version, updateType)
}

func (f *FilterAndUpCommand) validateFilterPaths() error {
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, p := range f.filterPaths {
		fullPath := file.ReplacePathSeparator(fmt.Sprintf("%s/%s/.semver.yaml", currentDir, p))
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return  fmt.Errorf("failed check path not exists: %s", p)
		}
	}
	return nil
}

func (f *FilterAndUpCommand) setPathsChangedInLastCommit() error {
	// TODO get list of paths to compare with flag
	// cmd $ git log --name-only --pretty=format: develop -p -1
	return nil
}
