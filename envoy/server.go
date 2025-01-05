// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/goauthlink/authlink/agent"
	"github.com/goauthlink/authlink/pkg/logging"
	"github.com/goauthlink/authlink/sdk/policy"
	rpc_code "google.golang.org/genproto/googleapis/rpc/code"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

type ServerOpt func(*Server)

func WithLogger(logger *slog.Logger) ServerOpt {
	return func(s *Server) {
		s.logger = logger
	}
}

type Server struct {
	server *grpc.Server
	logger *slog.Logger
	policy *agent.Policy
	addr   string
}

func New(addr string, policy *agent.Policy, opts ...ServerOpt) (*Server, error) {
	statshandler, err := newStatsHandler()
	if err != nil {
		return nil, err
	}

	srv := &Server{
		server: grpc.NewServer(grpc.StatsHandler(statshandler)),
		policy: policy,
		addr:   addr,
	}

	for _, o := range opts {
		o(srv)
	}

	if srv.logger == nil {
		srv.logger = logging.NewNullLogger()
	}

	return srv, nil
}

func (s *Server) Start(_ context.Context) error {
	authv3.RegisterAuthorizationServer(s.server, s)

	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen tcp for grpc server on %s: %w", s.addr, err)
	}

	s.logger.Info(fmt.Sprintf("grpc server is starting on %s", s.addr))

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
	in := policy.CheckInput{
		Uri:     rq.GetAttributes().GetRequest().GetHttp().GetPath(),
		Method:  rq.GetAttributes().GetRequest().GetHttp().GetMethod(),
		Headers: rq.GetAttributes().GetRequest().GetHttp().GetHeaders(),
	}

	out := &authv3.CheckResponse{}

	result, err := s.policy.Check(ctx, in)
	if err != nil {
		errmsg := fmt.Sprintf("envoy check handler: %s", err.Error())
		s.logger.Error(errmsg)
		out.Status = &rpc_status.Status{
			Code:    int32(rpc_code.Code_INTERNAL),
			Message: errmsg,
		}

		return out, err
	}

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
