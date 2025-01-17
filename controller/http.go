// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/goauthlink/authlink/pkg/logging"
	"github.com/goauthlink/authlink/pkg/metrics"
)

type httpServer struct {
	httpserver *http.Server
	cert       *tls.Certificate
	logger     *slog.Logger
}

type ServerOpt func(*httpServer)

func WithCert(cert *tls.Certificate) ServerOpt {
	return func(s *httpServer) {
		s.cert = cert
	}
}

func WithLogger(logger *slog.Logger) ServerOpt {
	return func(s *httpServer) {
		s.logger = logger
	}
}

func NewHttpServer(config Config, opts ...ServerOpt) (*httpServer, error) {
	httpSrv := &httpServer{
		httpserver: &http.Server{
			Addr: config.Addr,
		},
	}

	for _, o := range opts {
		o(httpSrv)
	}

	if httpSrv.logger == nil {
		httpSrv.logger = logging.NewNullLogger()
	}

	router := http.NewServeMux()
	router.Handle("POST /admissionv1/validate", newValidatingWebhookHandler())
	router.Handle("POST /admissionv1/validate/", newValidatingWebhookHandler())
	router.Handle("POST /admissionv1/inject", newInjectionWebhookHandler(config.InjectionConfig))
	router.Handle("POST /admissionv1/inject/", newInjectionWebhookHandler(config.InjectionConfig))

	metricsMiddleware, err := metrics.NewHTTPMiddleware(router)
	if err != nil {
		return nil, err
	}

	httpSrv.httpserver.Handler = metricsMiddleware

	return httpSrv, nil
}

func (httpSrv *httpServer) Start(_ context.Context) error {
	var listener net.Listener
	var err error

	httpSrv.logger.Info(fmt.Sprintf("http server is starting on %s", httpSrv.httpserver.Addr))

	if httpSrv.cert == nil {
		listener, err = net.Listen("tcp", httpSrv.httpserver.Addr)
	} else {
		listener, err = tls.Listen("tcp", httpSrv.httpserver.Addr, &tls.Config{
			Certificates: []tls.Certificate{*httpSrv.cert},
		})
	}
	if err != nil {
		return fmt.Errorf("http server listening: %w", err)
	}
	defer listener.Close()

	err = httpSrv.httpserver.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("https server listening: %w", err)
	}

	return nil
}

func (httpSrv *httpServer) Name() string {
	return "http"
}

func (httpSrv *httpServer) Shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	err := httpSrv.httpserver.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}

	return nil
}
