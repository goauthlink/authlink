// Copyright 2024 The AuthLink Authors.  All rights reserved.
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

	"github.com/goauthlink/authlink/pkg/logging"
	"github.com/goauthlink/authlink/pkg/metrics"
	sdk_policy "github.com/goauthlink/authlink/sdk/policy"
)

type HttpServer struct {
	httpserver *http.Server
	cert       *tls.Certificate
	logger     *slog.Logger
	policy     *Policy
}

type ServerOpt func(*HttpServer)

func WithCert(cert *tls.Certificate) ServerOpt {
	return func(s *HttpServer) {
		s.cert = cert
	}
}

func WithLogger(logger *slog.Logger) ServerOpt {
	return func(s *HttpServer) {
		s.logger = logger
	}
}

func NewHttpServer(addr string, policy *Policy, opts ...ServerOpt) (*HttpServer, error) {
	httpSrv := &HttpServer{
		httpserver: &http.Server{
			Addr: addr,
		},
		policy: policy,
	}

	for _, o := range opts {
		o(httpSrv)
	}

	if httpSrv.logger == nil {
		httpSrv.logger = logging.NewNullLogger()
	}

	if httpSrv.policy == nil {
		return nil, errors.New("policy checker are not configured for http server")
	}

	router := http.NewServeMux()
	router.Handle("POST /check", routerPostCheckHandler(httpSrv.policy, httpSrv.logger))

	metricsMiddleware, err := metrics.NewHTTPMiddleware(router)
	if err != nil {
		return nil, err
	}

	httpSrv.httpserver.Handler = metricsMiddleware

	return httpSrv, nil
}

func (srv *HttpServer) Start(_ context.Context) error {
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

func (httpServer *HttpServer) Shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := httpServer.httpserver.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}

	httpServer.logger.Info("http server stopped")

	return nil
}

func routerPostCheckHandler(policy *Policy, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := sdk_policy.CheckInput{
			Uri:     r.Header.Get("x-path"), // todo: move to settings
			Method:  strings.ToUpper(r.Header.Get("x-method")),
			Headers: map[string]string{},
		}

		for key, headerVal := range r.Header {
			in.Headers[strings.ToLower(key)] = strings.Join(headerVal, ",")
		}

		result, err := policy.Check(context.Background(), in)
		if err != nil {
			logger.Error(fmt.Sprintf("http check handler: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !result.Allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	})
}
