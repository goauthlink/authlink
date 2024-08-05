package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/auth-policy-controller/apc/internal/agent"
	"github.com/auth-policy-controller/apc/internal/logging"
	"github.com/spf13/cobra"
)

var agentCmd *cobra.Command

type agentCmdParams struct {
	logLevel string
	addr     string
}

func exitErr(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func init() {
	cmdParams := agentCmdParams{}

	agentCmd = &cobra.Command{
		Use:   "agent",
		Short: "Start policy agent",
		Run: func(cmd *cobra.Command, args []string) {
			config, err := prepareConfig(args, cmdParams)
			if err != nil {
				exitErr(err.Error())
				if err := agentCmd.Usage(); err != nil {
					exitErr(err.Error())
				}
			}

			agent, err := agent.Init(*config)
			if err != nil {
				exitErr(err.Error())
			}

			if err := agent.Run(); err != nil {
				exitErr(err.Error())
			}
		},
	}

	agentCmd.Flags().StringVar(&cmdParams.logLevel, "log-level", "info", "set log level (default info)")
	agentCmd.Flags().StringVar(&cmdParams.addr, "addr", ":8080", "set listening address of the http server (e.g., [ip]:<port>) (default [:8080])")
	agentCmd.SetUsageTemplate(`Usage:
  {{.UseLine}} [policy-file.yaml] [data-file.json (optional)]

Flags:
{{.LocalFlags.FlagUsages | trimRightSpace}}`)
}

const usageArgs = "arguments must by: [policy-file.yaml] [data-file.json (optional)]"

func prepareConfig(args []string, params agentCmdParams) (*agent.Config, error) {
	if len(args) == 0 || len(args) > 2 {
		return nil, fmt.Errorf(usageArgs)
	}

	config := agent.DefaultConfig()

	// load files
	for _, file := range args {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("load file %s: %w", file, err)
		}

		switch filepath.Ext(file) {
		case ".yaml":
			config.Policy = data
		case ".json":
			config.Data = data
		default:
			return nil, fmt.Errorf(usageArgs)
		}
	}
	if len(config.Policy) == 0 {
		return nil, fmt.Errorf(usageArgs)
	}

	// other params
	config.Addr = params.addr

	// parse log level
	parsedLogLevel, err := logging.ParseLevel(params.logLevel)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}
	config.LogLevel = parsedLogLevel

	return &config, nil
}
