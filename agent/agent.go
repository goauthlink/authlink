// Copyright 2024 The AuthPolicyController Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/auth-policy-controller/apc/agent/metrics"
	"github.com/auth-policy-controller/apc/pkg/policy"
)

type Agent struct {
	httpServer    *httpServer
	monitorServer *monitoringServer
	logger        *slog.Logger
	checker       *policy.Checker
	config        Config
	done          chan struct{}
}

func InitNewAgent(config Config) (*Agent, error) {
	agent := &Agent{
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: config.LogLevel,
		})),
		config: config,
		done:   make(chan struct{}, 1),
	}

	agent.logger.Info("start initing")

	agent.checker = policy.NewChecker()

	if err := agent.updateFiles(); err != nil {
		return nil, err
	}

	metrics, err := metrics.NewMetrics()
	if err != nil {
		return nil, err
	}

	agent.httpServer = initHttpServer(config, agent.logger, agent.checker, metrics)
	agent.logger.Info("agent inited")

	agent.monitorServer = initMonitoringServer(config.MonitoringAddr)
	agent.logger.Info("monitoring inited")

	return agent, nil
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		errchan <- a.httpServer.serve()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errchan <- a.monitorServer.serve()
	}()

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

	a.logger.Info("shutting down..")
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
	if err := a.checker.SetPolicy(policyData); err != nil {
		return fmt.Errorf("policy file updating failed: %w", err)
	}
	a.logger.Info("policy file updated")

	if len(a.config.DataFilePath) == 0 {
		return nil
	}

	dataData, err := os.ReadFile(a.config.DataFilePath)
	if err != nil {
		return fmt.Errorf("data file updating failed: %s", err)
	}

	var newData interface{}
	if err := json.Unmarshal(dataData, &newData); err != nil {
		return fmt.Errorf("parse data: %w", err)
	}
	a.checker.SetData(newData)

	a.logger.Info("data file updated")

	return nil
}

func (agent *Agent) shutdown(cancel context.CancelFunc, ctx context.Context) {
	cancel()
	if err := agent.httpServer.shutdown(ctx); err != nil {
		agent.logger.Error(err.Error())
	}
	agent.logger.Info("http server stopped")

	if err := agent.monitorServer.shutdown(ctx); err != nil {
		agent.logger.Error(err.Error())
	}
	agent.logger.Info("monitoring server stopped")
}

func (a *Agent) WaitUntilCompletion() {
	<-a.done
}
