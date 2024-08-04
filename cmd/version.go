package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show apc version",
	Run: func(cmd *cobra.Command, args []string) {
		println(string(os.Getenv("VERSION")))
	},
}
