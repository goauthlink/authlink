package cmd

import (
	"os"
	"path"

	"github.com/spf13/cobra"
)

var RootCommand *cobra.Command

func init() {
	RootCommand = &cobra.Command{
		Use:   path.Base(os.Args[0]),
		Short: "Authz Agent",
	}

	RootCommand.AddCommand(agentCmd)
	RootCommand.AddCommand(versionCmd)
}
