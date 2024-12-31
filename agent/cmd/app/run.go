// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package app

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/auth-request-agent/agent/agent"
	"github.com/auth-request-agent/agent/pkg/cmd"
	"github.com/auth-request-agent/agent/pkg/logging"
	"github.com/spf13/cobra"
)

type RunExtension interface {
	ConfigRunCmd(cmd *cobra.Command)
	Server(runArgs []string, agent *agent.Agent) (agent.Server, error)
}

type runCmdParams struct {
	logLevel           string
	logCheckResults    bool
	httpAddr           string
	observeAddr        string
	updateFilesSeconds int
	tlsDisable         bool
	tlsPrivateKeyPath  string
	tlsCertPath        string
}

func exitErr(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func newRunCmd(extensions ...RunExtension) *cobra.Command {
	cmdParams := runCmdParams{}
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start policy agent",
		Run: func(command *cobra.Command, args []string) {
			config, err := prepareConfig(args, cmdParams)
			if err != nil {
				exitErr(err.Error())
			}

			agent, err := agent.Init(*config)
			if err != nil {
				exitErr(err.Error())
			}

			for _, runExt := range extensions {
				server, err := runExt.Server(args, agent)
				if err != nil {
					exitErr(err.Error())
				}
				agent.AddServer(server)
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

	runCmd.Flags().StringVar(&cmdParams.httpAddr, "http-addr", ":8181", "set listening address of the http server (e.g., [ip]:<port>)")
	runCmd.Flags().StringVar(&cmdParams.observeAddr, "monitoring-addr", ":9191", "set listening address for the /health and /metrics (e.g., [ip]:<port>)")
	runCmd.Flags().BoolVar(&cmdParams.logCheckResults, "log-check-results", false, "log info about check requests results (default false)")
	runCmd.Flags().IntVar(&cmdParams.updateFilesSeconds, "update-files-seconds", 0, "set policy/data file updating period (seconds) (default 0 - do not update)")
	runCmd.Flags().BoolVar(&cmdParams.tlsDisable, "tls-disable", false, "disables TLS completely")
	runCmd.Flags().StringVar(&cmdParams.tlsPrivateKeyPath, "tls-private-key", "", "set path of TLS private key file")
	runCmd.Flags().StringVar(&cmdParams.tlsCertPath, "tls-cert", "", "set path of TLS certificate file")
	runCmd.SetUsageTemplate(`Usage:
  {{.UseLine}} [policy-file.yaml] [data-file.json (optional)]

Flags:
{{.LocalFlags.FlagUsages | trimRightSpace}}`)

	for _, runExt := range extensions {
		runExt.ConfigRunCmd(runCmd)
	}

	return runCmd
}

const usageArgs = "arguments must by: [policy-file.yaml] [data-file.json (optional)]"

func prepareConfig(args []string, params runCmdParams) (*agent.Config, error) {
	if len(args) == 0 || len(args) > 2 {
		return nil, errors.New(usageArgs)
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
			return nil, errors.New(usageArgs)
		}
	}

	// parse log level
	parsedLogLevel, err := logging.ParseLevel(params.logLevel)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}
	config.LogLevel = parsedLogLevel

	// other params
	config.HttpAddr = params.httpAddr
	config.MonitoringAddr = params.observeAddr
	config.LogCheckResults = params.logCheckResults
	config.UpdateFilesSeconds = params.updateFilesSeconds

	if !params.tlsDisable {
		cert, err := tls.LoadX509KeyPair(params.tlsCertPath, params.tlsPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		config.TLSCert = &cert
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("params validation error: %w", err)
	}

	return &config, nil
}
