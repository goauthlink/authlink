// Copyright 2024 The AuthPolicyController Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/auth-policy-controller/apc/agent/metrics"
	"github.com/auth-policy-controller/apc/pkg/policy"
)

type httpServer struct {
	srv *http.Server
}

func initHttpServer(config Config, logger *slog.Logger, checker *policy.Checker, metrics metrics.Metrics) *httpServer {
	router := http.NewServeMux()
	router.Handle("POST /check", routerPostCheckHandler(logger, checker, metrics))

	httpSrv := &httpServer{
		srv: &http.Server{
			Addr:    config.Addr,
			Handler: router,
		},
	}

	return httpSrv
}

func (httpServer *httpServer) serve() error {
	err := httpServer.srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server listening: %w", err)
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

func routerPostCheckHandler(logger *slog.Logger, checker *policy.Checker, metrics metrics.Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		defer func() {
			metrics.CheckRqTotalInc(context.Background())
		}()

		in := policy.CheckInput{
			Uri:     r.Header.Get("x-path"), // todo: move to settings
			Method:  r.Header.Get("x-method"),
			Headers: map[string]string{},
		}

		for key, headerVal := range r.Header {
			in.Headers[strings.ToLower(key)] = strings.Join(headerVal, ",")
		}

		// todo: allow_on_err

		allow, err := checker.Check(in)
		if err != nil {
			metrics.CheckRqFailedInc(context.Background())
			logger.Error(fmt.Sprintf("http check failed: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		finish := time.Since(start)
		metrics.CheckRqDurationObserve(context.Background(), finish.Milliseconds())

		if !allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	})
}
