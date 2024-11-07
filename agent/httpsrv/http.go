// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package httpsrv

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/auth-request-agent/agent/agent/observe"
	"github.com/auth-request-agent/agent/pkg/logging"
	"github.com/auth-request-agent/agent/pkg/policy"
)

type Server struct {
	httpserver  *http.Server
	cert        *tls.Certificate
	logger      *slog.Logger
	checkLogger *observe.CheckLogger
	checker     *policy.Checker
	metrics     observe.Metrics
}

type ServerOpt func(*Server)

func WithCheckLogger(checkLogger *observe.CheckLogger) ServerOpt {
	return func(s *Server) {
		s.checkLogger = checkLogger
	}
}

func WithCert(cert *tls.Certificate) ServerOpt {
	return func(s *Server) {
		s.cert = cert
	}
}

func WithLogger(logger *slog.Logger) ServerOpt {
	return func(s *Server) {
		s.logger = logger
	}
}

func WithChecker(checker *policy.Checker) ServerOpt {
	return func(s *Server) {
		s.checker = checker
	}
}

func WithMetrics(metrics observe.Metrics) ServerOpt {
	return func(s *Server) {
		s.metrics = metrics
	}
}

func New(addr string, opts ...ServerOpt) (*Server, error) {
	httpSrv := &Server{
		httpserver: &http.Server{
			Addr: addr,
		},
	}

	for _, o := range opts {
		o(httpSrv)
	}

	if httpSrv.checkLogger == nil {
		httpSrv.checkLogger = observe.NewNullCheckLogger()
	}

	if httpSrv.logger == nil {
		httpSrv.logger = logging.NewNullLogger()
	}

	if httpSrv.metrics == nil {
		httpSrv.metrics = observe.NewNullMetrics()
	}

	if httpSrv.checker == nil {
		return nil, errors.New("policy checker are not configured for http server")
	}

	router := http.NewServeMux()
	router.Handle("POST /check", routerPostCheckHandler(
		httpSrv.checker,
		httpSrv.checkLogger,
		httpSrv.logger,
		httpSrv.metrics,
	))
	httpSrv.httpserver.Handler = router

	return httpSrv, nil
}

func (srv *Server) Serve() error {
	var listener net.Listener
	var err error

	srv.logger.Info(fmt.Sprintf("http server is starting on %s", srv.httpserver.Addr))

	if srv.cert == nil {
		listener, err = net.Listen("tcp", srv.httpserver.Addr)
	} else {
		listener, err = tls.Listen("tcp", srv.httpserver.Addr, &tls.Config{
			Certificates: []tls.Certificate{*srv.cert},
		})
	}
	if err != nil {
		return fmt.Errorf("http server listening: %w", err)
	}
	defer listener.Close()

	err = srv.httpserver.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("https server listening: %w", err)
	}

	return nil
}

func (httpServer *Server) Shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := httpServer.httpserver.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}

	httpServer.logger.Info("http server stopped")

	return nil
}

func routerPostCheckHandler(checker *policy.Checker, checkLogger *observe.CheckLogger, logger *slog.Logger, metrics observe.Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		defer func() {
			finish := time.Since(start)
			metrics.CheckRqDurationObserve(context.Background(), finish.Milliseconds())
			metrics.CheckRqTotalInc(context.Background())
		}()

		in := policy.CheckInput{
			Uri:     r.Header.Get("x-path"), // todo: move to settings
			Method:  strings.ToUpper(r.Header.Get("x-method")),
			Headers: map[string]string{},
		}

		for key, headerVal := range r.Header {
			in.Headers[strings.ToLower(key)] = strings.Join(headerVal, ",")
		}

		// todo: allow_on_err

		result, err := checker.Check(in)
		if err != nil {
			metrics.CheckRqFailedInc(context.Background())
			logger.Error(fmt.Sprintf("http check failed: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		checkLogger.Log(in, *result)

		if !result.Allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	})
}
