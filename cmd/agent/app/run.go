// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/auth-request-agent/agent/agent"
	"github.com/auth-request-agent/agent/pkg/cmd"
	"github.com/auth-request-agent/agent/pkg/logging"
	"github.com/spf13/cobra"
)

type runCmdParams struct {
	logLevel           string
	logCheckResults    bool
	addr               string
	monitoringAddr     string
	updateFilesSeconds int
}

func exitErr(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func newRunCmd() *cobra.Command {
	cmdParams := runCmdParams{}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start policy agent",
		Run: func(command *cobra.Command, args []string) {
			config, err := prepareConfig(args, cmdParams)
			if err != nil {
				exitErr(err.Error())
			}

			agent, err := agent.InitNewAgent(*config)
			if err != nil {
				exitErr(err.Error())
			}

			stop := make(chan struct{}, 1)

			go func() {
				if err := agent.Run(stop); err != nil {
					exitErr(err.Error())
				}
			}()

			cmd.WaitSignal(stop)

			agent.WaitUntilCompletion()
		},
	}

	runCmd.Flags().StringVar(&cmdParams.logLevel, "log-level", "info", "set log level")

	runCmd.Flags().StringVar(&cmdParams.addr, "addr", ":8080", "set listening address of the http server (e.g., [ip]:<port>)")
	runCmd.Flags().StringVar(&cmdParams.monitoringAddr, "monitoring-addr", ":9191", "set listening address for the /health and /metrics (e.g., [ip]:<port>)")
	runCmd.Flags().BoolVar(&cmdParams.logCheckResults, "log-check-results", false, "log info about check requests results (default false)")
	runCmd.Flags().IntVar(&cmdParams.updateFilesSeconds, "update-files-seconds", 0, "set policy/data file updating period (seconds) (default 0 - do not update)")
	runCmd.SetUsageTemplate(`Usage:
  {{.UseLine}} [policy-file.yaml] [data-file.json (optional)]

Flags:
{{.LocalFlags.FlagUsages | trimRightSpace}}`)

	return runCmd
}

const usageArgs = "arguments must by: [policy-file.yaml] [data-file.json (optional)]"

func prepareConfig(args []string, params runCmdParams) (*agent.Config, error) {
	if len(args) == 0 || len(args) > 2 {
		return nil, fmt.Errorf(usageArgs)
	}

	config := agent.DefaultConfig()

	// load files
	for _, file := range args {
		switch filepath.Ext(file) {
		case ".yaml":
			config.PolicyFilePath = file
		case ".json":
			config.DataFilePath = file
		default:
			return nil, fmt.Errorf(usageArgs)
		}
	}

	// parse log level
	parsedLogLevel, err := logging.ParseLevel(params.logLevel)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}
	config.LogLevel = parsedLogLevel

	// other params
	config.Addr = params.addr
	config.MonitoringAddr = params.monitoringAddr
	config.LogCheckResults = params.logCheckResults
	config.UpdateFilesSeconds = params.updateFilesSeconds

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("params validation error: %w", err)
	}

	return &config, nil
}
