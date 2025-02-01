// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"github.com/goauthlink/authlink/agent/monitoring"
	"github.com/goauthlink/authlink/pkg/runtime"
	"github.com/goauthlink/authlink/sdk/policy"
)

type Config struct {
	HttpAddr        string
	MonitoringAddr  string
	LogLevel        slog.Level
	LogCheckResults bool
	DiscoverAddr    string
	PolicyFilePath  string
	DataFilePath    string
	TLSCert         *tls.Certificate
}

func DefaultConfig() Config {
	return Config{
		HttpAddr:        ":8181",
		MonitoringAddr:  ":9191",
		LogLevel:        slog.LevelInfo,
		LogCheckResults: false,
	}
}

type Agent struct {
	runtime *runtime.Runtime
	policy  *Policy
	logger  *slog.Logger
	config  Config
}

func Init(config Config) (*Agent, error) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: config.LogLevel,
	}))

	agent := &Agent{
		config: config,
		logger: logger,
	}

	logger.Info("start initing")

	var checkLogger *CheckLogger
	if config.LogCheckResults {
		checkLogger = NewCheckLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	}

	agent.policy = NewPolicy(policy.NewChecker(), checkLogger)

	if err := agent.loadFiles(); err != nil {
		return nil, fmt.Errorf("loading files: %w", err)
	}

	httpServerOptions := []ServerOpt{
		WithLogger(logger),
	}

	if config.TLSCert != nil {
		httpServerOptions = append(httpServerOptions, WithCert(config.TLSCert))
	}

	httpServer, err := NewHttpServer(config.HttpAddr, agent.policy, httpServerOptions...)
	if err != nil {
		return nil, fmt.Errorf("initing http server: %w", err)
	}

	monitoringServerOpions := []monitoring.ServerOpt{
		monitoring.WithLogger(logger),
	}
	monitoringServer, err := monitoring.NewServer(config.MonitoringAddr, monitoringServerOpions...)
	if err != nil {
		return nil, err
	}

	agent.runtime = runtime.NewRuntime([]runtime.Server{
		httpServer,
		monitoringServer,
	}, logger)

	// discovery init

	logger.Info("agent is ready")

	return agent, nil
}

func (a *Agent) AddServer(server runtime.Server) {
	a.runtime.AddServer(server)
}

func (a *Agent) Run() error {
	return a.runtime.Start()
}

func (a *Agent) Logger() *slog.Logger {
	return a.logger
}

func (a *Agent) Policy() *Policy {
	return a.policy
}

func (a *Agent) loadFiles() error {
	if len(a.config.PolicyFilePath) == 0 {
		return nil
	}

	policyData, err := os.ReadFile(a.config.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("policy file loading failed: %w", err)
	}
	if err := a.policy.SetPolicy(policyData); err != nil {
		return fmt.Errorf("policy file updating failed: %w", err)
	}
	a.logger.Info("policy file loaded")

	if len(a.config.DataFilePath) == 0 {
		return nil
	}

	data, err := os.ReadFile(a.config.DataFilePath)
	if err != nil {
		return fmt.Errorf("data file loading failed: %s", err)
	}

	if err := a.policy.SetData(data); err != nil {
		return fmt.Errorf("loading data.json: %w", err)
	}

	a.logger.Info("data file loaded")

	return nil
}
