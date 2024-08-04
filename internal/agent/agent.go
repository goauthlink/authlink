package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/auth-policy-controller/apc/internal/policy"
)

type Agent struct {
	server *httpServer
	logger *slog.Logger
}

func Init(config Config) (*Agent, error) {
	agent := &Agent{
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: config.LogLevel,
		})),
	}

	agent.logger.Info("init policy")
	policyData, err := os.ReadFile(config.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("init policy: %w", err)
	}

	prepConfig, err := policy.PrepareConfig(policyData)
	if err != nil {
		return nil, fmt.Errorf("init policy: %w", err)
	}

	checker := policy.NewChecker(prepConfig)

	agent.logger.Info("init http server")
	agent.server = initHttpServer(config, agent.logger, checker)

	return agent, nil
}

func (agent *Agent) Run() error {
	wg := sync.WaitGroup{}
	var reserr error
	errchan := make(chan error, 1)

	ctx, cancel := context.WithCancel(context.Background())

	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		close(errchan)
	}()

	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := agent.server.serve()
		if err != nil {
			errchan <- err
		}
	}()

	select {
	case err := <-errchan:
		reserr = err
		agent.logger.Error(err.Error())
		break
	case <-signalCh:
		agent.logger.Info("received exit signal")
		break
	}

	agent.Shutdown(cancel, ctx)

	wg.Wait()

	return reserr
}

func (agent *Agent) Shutdown(cancel context.CancelFunc, ctx context.Context) {
	cancel()
	agent.logger.Info("shutdown server")
	if err := agent.server.shutdown(ctx); err != nil {
		agent.logger.Error(err.Error())
	}
}
