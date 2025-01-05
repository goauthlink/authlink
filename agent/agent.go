// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/goauthlink/authlink/agent/monitoring"
	"github.com/goauthlink/authlink/sdk/policy"
)

type Server interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

type Agent struct {
	servers []Server
	logger  *slog.Logger
	policy  *Policy
	config  Config
	done    chan struct{}
}

func Init(config Config) (*Agent, error) {
	agent := &Agent{
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: config.LogLevel,
		})),
		config: config,
		done:   make(chan struct{}, 1),
	}

	agent.logger.Info("start initing")

	var checkLogger *CheckLogger
	if config.LogCheckResults {
		checkLogger = NewCheckLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	}

	agent.policy = NewPolicy(policy.NewChecker(), checkLogger)

	if err := agent.updateFiles(); err != nil {
		return nil, err
	}

	httpServerOptions := []ServerOpt{
		WithLogger(agent.logger),
	}

	if config.TLSCert != nil {
		httpServerOptions = append(httpServerOptions, WithCert(config.TLSCert))
	}

	httpServer, err := NewHttpServer(config.HttpAddr, agent.policy, httpServerOptions...)
	if err != nil {
		return nil, fmt.Errorf("init http server: %w", err)
	}

	monitoringServerOpions := []monitoring.ServerOpt{
		monitoring.WithLogger(agent.logger),
	}
	monitoringServer, err := monitoring.NewServer(config.MonitoringAddr, monitoringServerOpions...)
	if err != nil {
		return nil, err
	}

	agent.servers = []Server{
		httpServer,
		monitoringServer,
	}

	agent.logger.Info("agent inited")

	return agent, nil
}

func (a *Agent) AddServer(server Server) {
	a.servers = append(a.servers, server)
}

func (a *Agent) Run(stop chan struct{}) error {
	wg := sync.WaitGroup{}
	var reserr error

	ctx, cancel := context.WithCancel(context.Background())

	errchan := make(chan error)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for err := range errchan {
			if err != nil {
				a.logger.Error(err.Error())
				if reserr == nil {
					reserr = err
				}
			}
		}
	}()

	for _, srv := range a.servers {
		wg.Add(1)
		go func(srv Server) {
			defer wg.Done()
			errchan <- srv.Start(ctx)
		}(srv)
	}

	if a.config.UpdateFilesSeconds > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ticker := time.NewTicker(time.Second * time.Duration(a.config.UpdateFilesSeconds))

			a.logger.Info("start updating files")
			for {
				select {
				case <-ticker.C:
					if err := a.updateFiles(); err != nil {
						a.logger.Error(fmt.Sprintf("updating files failed: %s", err.Error()))
					}
				case <-ctx.Done():
					a.logger.Info("stop updating files")
					return
				}
			}
		}()
	}

	a.logger.Info("agent started")

	<-stop
	a.logger.Info("received exit signal")

	a.shutdown(cancel, ctx)
	close(errchan)
	wg.Wait()
	a.logger.Info("agent shutdown")
	close(a.done)

	return reserr
}

func (a *Agent) updateFiles() error {
	policyData, err := os.ReadFile(a.config.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("policy file updating failed: %w", err)
	}
	if err := a.policy.SetPolicy(policyData); err != nil {
		return fmt.Errorf("policy file updating failed: %w", err)
	}
	a.logger.Info("policy file updated")

	if len(a.config.DataFilePath) == 0 {
		return nil
	}

	data, err := os.ReadFile(a.config.DataFilePath)
	if err != nil {
		return fmt.Errorf("data file updating failed: %s", err)
	}

	if err := a.policy.SetData(data); err != nil {
		return fmt.Errorf("loading data.json: %w", err)
	}

	a.logger.Info("data file updated")

	return nil
}

func (agent *Agent) shutdown(cancel context.CancelFunc, ctx context.Context) {
	cancel()
	for _, srv := range agent.servers {
		srv.Shutdown(ctx) //nolint: errcheck
	}
}

func (a *Agent) WaitUntilCompletion() {
	<-a.done
}

func (a *Agent) Logger() *slog.Logger {
	return a.logger
}

func (a *Agent) Policy() *Policy {
	return a.policy
}
