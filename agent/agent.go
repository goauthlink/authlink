// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/goauthlink/authlink/agent/monitoring"
	"github.com/goauthlink/authlink/pkg/runtime"
	"github.com/goauthlink/authlink/sdk/policy"
)

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

	updater := newUpdater(config, logger, agent.policy)
	if err := updater.updateFiles(); err != nil {
		return nil, err
	}

	httpServerOptions := []ServerOpt{
		WithLogger(logger),
	}

	if config.TLSCert != nil {
		httpServerOptions = append(httpServerOptions, WithCert(config.TLSCert))
	}

	httpServer, err := NewHttpServer(config.HttpAddr, agent.policy, httpServerOptions...)
	if err != nil {
		return nil, fmt.Errorf("init http server: %w", err)
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

	if config.UpdateFilesSeconds > 0 {
		agent.runtime.AddServer(updater)
	}

	logger.Info("agent inited")

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
