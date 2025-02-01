// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/goauthlink/authlink/api"
	"github.com/goauthlink/authlink/controller/kube"
	"google.golang.org/grpc"
)

type pListener struct {
	logger   *slog.Logger
	clientId kube.ClientId
	stream   grpc.ServerStreamingServer[api.PolicySnapshot]
}

func newPolicyListener(logger *slog.Logger, clientId kube.ClientId, stream grpc.ServerStreamingServer[api.PolicySnapshot]) *pListener {
	return &pListener{
		logger:   logger,
		clientId: clientId,
		stream:   stream,
	}
}

func (pl *pListener) Update(snapshot kube.NsPolicySnapshot) {
	polices := []string{}
	for _, p := range snapshot.Policies {
		policyJson, err := json.Marshal(p.Config)
		if err != nil {
			pl.logger.Error(fmt.Sprintf("watcher listener can't marshal policy to json %s/%s: %s",
				pl.clientId.Name, pl.clientId.Namespace, err.Error()))
			return
		}
		polices = append(polices, string(policyJson))
	}

	resp := api.PolicySnapshot{
		Policy: polices,
	}

	if err := pl.stream.Send(&resp); err != nil {
		pl.logger.Error(fmt.Sprintf("failed send to stream for %s/%s: %s", pl.clientId.Name, pl.clientId.Namespace, err.Error()))
		pl.stream.Context().Err()
		// todo: finish stream after 3 times
	}
}

type discoveryServer struct {
	api.UnimplementedDicsoveryServiceServer
	ctx           context.Context
	config        Config
	logger        *slog.Logger
	grpcServer    *grpc.Server
	policyWatcher *kube.PolicyWatcher
}

func newDiscoveryServer(config Config, logger *slog.Logger, kubeapi *kube.Api) (*discoveryServer, error) {
	policyWatcher, err := kube.NewPolicyWatcher(logger, kubeapi)
	if err != nil {
		return nil, err
	}

	ds := &discoveryServer{
		config:        config,
		logger:        logger,
		policyWatcher: policyWatcher,
	}
	ds.grpcServer = grpc.NewServer()

	api.RegisterDicsoveryServiceServer(ds.grpcServer, ds)

	return ds, nil
}

func (s *discoveryServer) Start(ctx context.Context) error {
	s.ctx = ctx
	tcpListener, err := net.Listen("tcp", s.config.DiscoveryAddr)
	if err != nil {
		return fmt.Errorf("listen tcp for discovery server on %s: %w", s.config.DiscoveryAddr, err)
	}

	s.logger.Info(fmt.Sprintf("discovery server is starting on %s", s.config.DiscoveryAddr))

	if err := s.grpcServer.Serve(tcpListener); err != nil {
		return fmt.Errorf("serve discovery server: %w", err)
	}

	return nil
}

func (s *discoveryServer) Policy(rq *api.GetPolicy, stream grpc.ServerStreamingServer[api.PolicySnapshot]) error {
	clientId := &kube.ClientId{
		Name:      rq.Id,
		Namespace: rq.Namespace,
		Labels:    rq.Labels,
	}

	listener := newPolicyListener(s.logger, *clientId, stream)

	if err := s.policyWatcher.Subscribe(*clientId, listener); err != nil {
		s.logger.Error(fmt.Sprintf("failed subscribe %s/%s: %s", rq.Id, rq.Namespace, err.Error()))
		return err
	}
	defer s.policyWatcher.Unsubscribe(*clientId)

	deadlineTimer := time.NewTimer(time.Minute * 30)

	select {
	case <-deadlineTimer.C:
		s.logger.Info(fmt.Sprintf("stream done by timeout for %s/%s", clientId.Name, clientId.Namespace))
		break
	case <-stream.Context().Done():
		s.logger.Info(fmt.Sprintf("stream context done for %s/%s", clientId.Name, clientId.Namespace))
		break
	case <-s.ctx.Done():
		break
	}

	return nil
}

func (s *discoveryServer) Shutdown(_ context.Context) error {
	return nil
}

func (s *discoveryServer) Name() string {
	return "discovery"
}
