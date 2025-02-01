// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package run

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"

	"github.com/goauthlink/authlink/agent"
	"github.com/goauthlink/authlink/pkg"
	"github.com/goauthlink/authlink/pkg/logging"
	"github.com/goauthlink/authlink/pkg/runtime"
)

type AgentRunExt interface {
	Flags(fs *flag.FlagSet)
	Server(runArgs []string, agent *agent.Agent) (runtime.Server, error)
}

type runCmdParams struct {
	logLevel          string
	logCheckResults   bool
	httpAddr          string
	monitoringAddr    string
	discoveryAddr     string
	policyFilePath    string
	dataFilePath      string
	tlsDisable        bool
	tlsPrivateKeyPath string
	tlsCertPath       string
}

func RunCmd(args []string, extentions []AgentRunExt) error {
	cmdParams := runCmdParams{}

	flagSet := flag.NewFlagSet("run", flag.ExitOnError)

	flagSet.StringVar(&cmdParams.logLevel, "log-level", "info", "set log level")
	flagSet.StringVar(&cmdParams.httpAddr, "http-addr", ":8181", "set listening address of the http server (e.g., [ip]:<port>)")
	flagSet.StringVar(&cmdParams.monitoringAddr, "monitoring-addr", ":9191", "set listening address for the /health and /metrics (e.g., [ip]:<port>)")
	flagSet.BoolVar(&cmdParams.logCheckResults, "log-check-results", false, "log info about check requests results (default false)")
	flagSet.StringVar(&cmdParams.discoveryAddr, "discovery-addr", "", "discovery server host (default: empty, without discovering policies)")
	flagSet.StringVar(&cmdParams.policyFilePath, "policy-file", "", "set path of policy yaml for initing agent (default: '' - without initing, discovery is required)")
	flagSet.StringVar(&cmdParams.dataFilePath, "data-file", "", "set path of data json for using in policy (default: '' - without loading data")
	flagSet.BoolVar(&cmdParams.tlsDisable, "tls-disable", false, "disables TLS completely")
	flagSet.StringVar(&cmdParams.tlsPrivateKeyPath, "tls-key-file", "", "set path of TLS private key file")
	flagSet.StringVar(&cmdParams.tlsCertPath, "tls-cert-file", "", "set path of TLS certificate file")
	version := flagSet.Bool("version", false, "show version")

	for _, runExt := range extentions {
		runExt.Flags(flagSet)
	}

	if err := flagSet.Parse(args[1:]); err != nil {
		return fmt.Errorf("parsing flags: %s", err.Error())
	}

	if *version {
		fmt.Print(pkg.Version)
		return nil
	}

	config, err := prepareConfig(cmdParams)
	if err != nil {
		flagSet.Usage()
		return err
	}

	agent, err := agent.Init(*config)
	if err != nil {
		return err
	}

	for _, runExt := range extentions {
		server, err := runExt.Server(args, agent)
		if err != nil {
			return err
		}
		agent.AddServer(server)
	}

	if err := agent.Run(); err != nil {
		return err
	}

	return nil
}

func prepareConfig(params runCmdParams) (*agent.Config, error) {
	config := agent.DefaultConfig()

	if len(params.discoveryAddr) > 0 && (len(params.policyFilePath) > 0 || len(params.dataFilePath) > 0) {
		return nil, fmt.Errorf("it is possible to use only -discovery-addr or -policy-file/-data-file at the same time")
	}

	if len(params.discoveryAddr) == 0 && len(params.policyFilePath) == 0 {
		return nil, errors.New("-discovery-addr or -policy-file are required for policy loading")
	}

	// parse log level
	parsedLogLevel, err := logging.ParseLevel(params.logLevel)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}
	config.LogLevel = parsedLogLevel

	// other params
	config.HttpAddr = params.httpAddr
	config.MonitoringAddr = params.monitoringAddr
	config.LogCheckResults = params.logCheckResults
	config.DiscoverAddr = params.discoveryAddr
	config.PolicyFilePath = params.policyFilePath
	config.DataFilePath = params.dataFilePath

	if !params.tlsDisable {
		if len(params.tlsPrivateKeyPath) == 0 {
			return nil, errors.New("TLS private key is required when TLS is enabled")
		}

		if len(params.tlsCertPath) == 0 {
			return nil, errors.New("TLS certificate is required when TLS is enabled")
		}

		cert, err := tls.LoadX509KeyPair(params.tlsCertPath, params.tlsPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		config.TLSCert = &cert
	}

	return &config, nil
}
