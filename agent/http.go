// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

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

type httpServer struct {
	srv         *http.Server
	cert        *tls.Certificate
	logger      *slog.Logger
	checkLogger *observe.CheckLogger
	checker     *policy.Checker
	metrics     observe.Metrics
}

type httpServerOpt func(*httpServer)

func withCheckLogger(checkLogger *observe.CheckLogger) httpServerOpt {
	return func(s *httpServer) {
		s.checkLogger = checkLogger
	}
}

func withCert(cert *tls.Certificate) httpServerOpt {
	return func(s *httpServer) {
		s.cert = cert
	}
}

func withLogger(logger *slog.Logger) httpServerOpt {
	return func(s *httpServer) {
		s.logger = logger
	}
}

func withChecker(checker *policy.Checker) httpServerOpt {
	return func(s *httpServer) {
		s.checker = checker
	}
}

func withMetrics(metrics observe.Metrics) httpServerOpt {
	return func(s *httpServer) {
		s.metrics = metrics
	}
}

func initHttpServer(addr string, opts ...httpServerOpt) (*httpServer, error) {
	httpSrv := &httpServer{
		srv: &http.Server{
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
		return nil, errors.New("metrics provider are not configured")
	}

	if httpSrv.checker == nil {
		return nil, errors.New("policy checker are not configured")
	}

	router := http.NewServeMux()
	router.Handle("POST /check", routerPostCheckHandler(
		httpSrv.checker,
		httpSrv.checkLogger,
		httpSrv.logger,
		httpSrv.metrics,
	))
	httpSrv.srv.Handler = router

	return httpSrv, nil
}

func (httpServer *httpServer) serve() error {
	var listener net.Listener
	var err error

	if httpServer.cert == nil {
		listener, err = net.Listen("tcp", httpServer.srv.Addr)
	} else {
		listener, err = tls.Listen("tcp", httpServer.srv.Addr, &tls.Config{
			Certificates: []tls.Certificate{*httpServer.cert},
		})
	}
	if err != nil {
		return fmt.Errorf("http server listening: %w", err)
	}
	defer listener.Close()

	err = httpServer.srv.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("https server listening: %w", err)
	}

	return nil
}

func (httpServer *httpServer) shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := httpServer.srv.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}

	return nil
}

func routerPostCheckHandler(checker *policy.Checker, checkLogger *observe.CheckLogger, logger *slog.Logger, metrics observe.Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		defer func() {
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

		finish := time.Since(start)
		metrics.CheckRqDurationObserve(context.Background(), finish.Milliseconds())

		checkLogger.Log(in, *result)

		if !result.Allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	})
}
