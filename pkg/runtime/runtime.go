// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type Server interface {
	Name() string
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

type Runtime struct {
	servers []Server
	logger  *slog.Logger
	errchan chan error
	stop    chan struct{}
	ctx     context.Context
}

func NewRuntime(servers []Server, logger *slog.Logger) *Runtime {
	return &Runtime{
		servers: servers,
		errchan: make(chan error),
		stop:    make(chan struct{}),
		logger:  logger,
	}
}

func (r *Runtime) AddServer(server Server) {
	r.servers = append(r.servers, server)
}

func (r *Runtime) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	r.ctx = ctx

	var exiterr error
	serversWg := sync.WaitGroup{}

	errWg := sync.WaitGroup{}
	errWg.Add(1)
	go func() {
		defer errWg.Done()
		stopped := false
		for {
			err, ok := <-r.errchan
			if !ok {
				return
			}
			if err != nil {
				if !stopped {
					close(r.stop)
					stopped = true
					exiterr = err
				}
				r.logger.Error(err.Error())
			}
		}
	}()

	for _, srv := range r.servers {
		serversWg.Add(1)
		go func(srv Server) {
			r.logger.Info(fmt.Sprintf("%s starts", srv.Name()))
			if err := srv.Start(r.ctx); err != nil {
				r.errchan <- err
			}
			serversWg.Done()
			r.logger.Info(fmt.Sprintf("%s stopped", srv.Name()))
		}(srv)
	}

	r.logger.Info("runtime started")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigs:
		r.logger.Info("received exit signal")
		cancel()
		r.shutdown()
		break
	case <-r.stop:
		r.logger.Info("exit with err")
		cancel()
		r.shutdown()
		break
	}

	serversWg.Wait()

	close(r.errchan)

	errWg.Wait()

	r.logger.Info("runtime stopped")

	return exiterr
}

func (r *Runtime) Stop() {
	close(r.stop)
}

func (r *Runtime) shutdown() {
	r.logger.Info("start runtime shutdown")
	for _, srv := range r.servers {
		r.logger.Info(fmt.Sprintf("%s stops", srv.Name()))
		if err := srv.Shutdown(r.ctx); err != nil {
			r.logger.Info(fmt.Sprintf("%s stoping failed: %s", srv.Name(), err.Error()))
		}
	}
}
