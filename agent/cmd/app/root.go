package app

import (
	"os"
	"path"

	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   path.Base(os.Args[0]),
		Short: "Auth policy agent",
	}

	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}