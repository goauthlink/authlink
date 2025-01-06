// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package envoy

import (
	"context"
	"fmt"

	"github.com/goauthlink/authlink/pkg/metrics"
	grpcstats "google.golang.org/grpc/stats"
)

type rpcStatCtxKey struct{}

type statshandler struct {
	grpcRqDuration metrics.Metric
}

func newStatsHandler() (*statshandler, error) {
	grpcRqDuration, err := metrics.NewHistogram(
		"envoy_grpc_handler_duration_seconds",
		"A histogram of duration for grpc requests.",
		0.00005,
		0.0001,
		0.0005,
		0.001,
		0.003,
		0.005,
		0.01,
		0.03,
		0.06,
		0.1,
		0.3,
		0.6,
		1,
	)
	if err != nil {
		return nil, fmt.Errorf("new grpc stats handler: %w", err)
	}

	return &statshandler{
		grpcRqDuration: grpcRqDuration,
	}, nil
}

func (sh *statshandler) TagRPC(ctx context.Context, stat *grpcstats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, rpcStatCtxKey{}, stat)
}

func (sh *statshandler) HandleRPC(ctx context.Context, stats grpcstats.RPCStats) {
	if ctx == nil {
		return
	}
	if end, ok := stats.(*grpcstats.End); ok {
		latency := end.EndTime.Sub(end.BeginTime)
		sh.grpcRqDuration.Record(float64(latency), nil)
	}
}

func (sh *statshandler) TagConn(ctx context.Context, stat *grpcstats.ConnTagInfo) context.Context {
	return ctx
}

func (sh *statshandler) HandleConn(ctx context.Context, stat grpcstats.ConnStats) {}
