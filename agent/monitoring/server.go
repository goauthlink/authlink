// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package monitoring

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/goauthlink/authlink/pkg/metrics"
)

type Server struct {
	srv    *http.Server
	logger *slog.Logger
}

type ServerOpt func(*Server)

func WithLogger(logger *slog.Logger) ServerOpt {
	return func(s *Server) {
		s.logger = logger
	}
}

func NewServer(addr string, opts ...ServerOpt) (*Server, error) {
	promhandler, err := metrics.RegisterPrometheusExporter()
	if err != nil {
		return nil, fmt.Errorf("init monitoring server: %w", err)
	}

	router := http.NewServeMux()
	router.Handle("GET /metrics", promhandler)
	router.Handle("GET /health", routerGetHealtzHandler())

	monitoringSrv := &Server{
		srv: &http.Server{
			Addr:    addr,
			Handler: router,
		},
	}

	for _, o := range opts {
		o(monitoringSrv)
	}

	return monitoringSrv, nil
}

func routerGetHealtzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func (monitorSrv *Server) Name() string {
	return "http"
}

func (monitorSrv *Server) Start(_ context.Context) error {
	monitorSrv.logger.Info(fmt.Sprintf("monitor server is starting on %s", monitorSrv.srv.Addr))

	if err := monitorSrv.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("monitoring server listening: %w", err)
	}

	return nil
}

func (monitorSrv *Server) Shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := monitorSrv.srv.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown monitoring server: %w", err)
	}

	monitorSrv.logger.Info("monitor server stopped")

	return nil
}
