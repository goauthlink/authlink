package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/auth-policy-controller/apc/pkg/policy"
)

type Agent struct {
	server  *httpServer
	logger  *slog.Logger
	checker *policy.Checker
	config  Config
	done    chan struct{}
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

	agent.server = initHttpServer(config, agent.logger, agent.checker)

	agent.logger.Info("agent inited")

	return agent, nil
}

func (a *Agent) Run(stop chan struct{}) error {
	wg := sync.WaitGroup{}
	var reserr error
	errchan := make(chan error, 1)

	defer close(errchan)

	ctx, cancel := context.WithCancel(context.Background())

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := a.server.serve()
		if err != nil {
			errchan <- err
		}
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

	select {
	case err := <-errchan:
		reserr = err
		a.logger.Error(err.Error())
		break
	case <-stop:
		a.logger.Info("received exit signal")
		break
	}

	a.Shutdown(cancel, ctx)
	wg.Wait()

	a.logger.Info("agent stopped")

	close(a.done)

	return reserr
}

func (a *Agent) WaitUntilCompletion() {
	<-a.done
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

func (agent *Agent) Shutdown(cancel context.CancelFunc, ctx context.Context) {
	cancel()
	if err := agent.server.shutdown(ctx); err != nil {
		agent.logger.Error(err.Error())
	}
}
