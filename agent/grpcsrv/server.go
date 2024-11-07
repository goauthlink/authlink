// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package grpcsrv

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/auth-request-agent/agent/agent/observe"
	"github.com/auth-request-agent/agent/pkg/logging"
	"github.com/auth-request-agent/agent/pkg/policy"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	rpc_code "google.golang.org/genproto/googleapis/rpc/code"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

type ServerOpt func(*Server)

func WithCheckLogger(checkLogger *observe.CheckLogger) ServerOpt {
	return func(s *Server) {
		s.checkLogger = checkLogger
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

type Server struct {
	server      *grpc.Server
	logger      *slog.Logger
	checkLogger *observe.CheckLogger
	checker     *policy.Checker
	metrics     observe.Metrics
	addr        string
}

func New(addr string, opts ...ServerOpt) (*Server, error) {
	srv := &Server{
		server: grpc.NewServer([]grpc.ServerOption{}...),
		addr:   addr,
	}

	for _, o := range opts {
		o(srv)
	}

	if srv.checkLogger == nil {
		srv.checkLogger = observe.NewNullCheckLogger()
	}

	if srv.logger == nil {
		srv.logger = logging.NewNullLogger()
	}

	if srv.metrics == nil {
		srv.metrics = observe.NewNullMetrics()
	}

	if srv.checker == nil {
		return nil, errors.New("policy checker are not configured for grpc server")
	}

	return srv, nil
}

func (s *Server) Serve() error {
	authv3.RegisterAuthorizationServer(s.server, s)

	s.logger.Info(fmt.Sprintf("grpc server is starting on %s", s.addr))

	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen tcp for grpc server on %s: %w", s.addr, err)
	}

	if err := s.server.Serve(listener); err != nil {
		return fmt.Errorf("serve grpc server: %w", err)
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.server.Stop()
	s.logger.Info("grpc server stopped")
	return nil
}

func (s *Server) Check(ctx context.Context, rq *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := time.Now()

	defer func() {
		finish := time.Since(start)
		s.metrics.CheckRqDurationObserve(context.Background(), finish.Milliseconds())
		s.metrics.CheckRqTotalInc(context.Background())
	}()

	in := policy.CheckInput{
		Uri:     rq.GetAttributes().GetRequest().GetHttp().GetPath(),
		Method:  rq.GetAttributes().GetRequest().GetHttp().GetMethod(),
		Headers: rq.GetAttributes().GetRequest().GetHttp().GetHeaders(),
	}

	out := &authv3.CheckResponse{}

	result, err := s.checker.Check(in)
	if err != nil {
		s.metrics.CheckRqFailedInc(context.Background())
		errmsg := fmt.Sprintf("http check failed: %s", err.Error())
		s.logger.Error(errmsg)
		out.Status = &rpc_status.Status{
			Code:    int32(rpc_code.Code_INTERNAL),
			Message: errmsg,
		}

		return out, err
	}

	s.checkLogger.Log(in, *result)

	if !result.Allow {
		out.Status = &rpc_status.Status{
			Code: int32(rpc_code.Code_PERMISSION_DENIED),
		}

		return out, nil
	}

	out.Status = &rpc_status.Status{
		Code: int32(rpc_code.Code_OK),
	}

	return out, nil
}
