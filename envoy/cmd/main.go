// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/goauthlink/authlink/agent"
	"github.com/goauthlink/authlink/agent/cmd/run"
	"github.com/goauthlink/authlink/envoy"
	"github.com/goauthlink/authlink/pkg/runtime"
)

var grpcAddr string

type EnvoyExtension struct{}

func NewEnvoyExtension() *EnvoyExtension {
	return &EnvoyExtension{}
}

func (r *EnvoyExtension) Flags(fs *flag.FlagSet) {
	fs.StringVar(&grpcAddr, "envoy-grpc-addr", ":8282", "set listening address of the envoy grpc server (e.g., [ip]:<port>)")
}

func (r *EnvoyExtension) Server(runArgs []string, agent *agent.Agent) (runtime.Server, error) {
	envoyServer, err := envoy.New(grpcAddr, agent.Policy(), envoy.WithLogger(agent.Logger()))
	if err != nil {
		return nil, fmt.Errorf("start envoy server: %w", err)
	}

	return envoyServer, nil
}

func main() {
	if err := run.RunCmd(os.Args, []run.AgentRunExt{}); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
