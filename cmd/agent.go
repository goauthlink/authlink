package cmd

import (
	"fmt"
	"os"

	"github.com/auth-policy-controller/apc/internal/agent"
	"github.com/auth-policy-controller/apc/internal/logging"
	"github.com/spf13/cobra"
)

var agentCmd *cobra.Command

var (
	logLevel string
	addr     string
)

func init() {
	agentCmd = &cobra.Command{
		Use:   "agent",
		Short: "Start policy agent",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				agentCmd.Usage()
				fmt.Println("error: [policy-file] is required argument")
				os.Exit(1)
			}

			config := agent.DefaultConfig()

			config.PolicyFile = args[0]
			config.Addr = addr

			parsedLogLevel, err := logging.ParseLevel(logLevel)
			if err != nil {
				fmt.Printf("init logger: %e", err)
				os.Exit(1)
			}
			config.LogLevel = parsedLogLevel

			agent, err := agent.Init(config)
			if err != nil {
				fmt.Print(err.Error())
				os.Exit(1)
			}

			if err := agent.Run(); err != nil {
				fmt.Print(err.Error())
				os.Exit(1)
			}
		},
	}

	agentCmd.Flags().StringVar(&logLevel, "log-level", "info", "set log level (default info)")
	agentCmd.Flags().StringVar(&addr, "addr", ":8080", "set listening address of the http server (e.g., [ip]:<port>) (default [:8080])")
	agentCmd.SetUsageTemplate(`Usage:
  {{.UseLine}} [policy-file]

Flags:
{{.LocalFlags.FlagUsages | trimRightSpace}}`)
}
