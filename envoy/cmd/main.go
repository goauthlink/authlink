// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/goauthlink/authlink/agent"
	"github.com/goauthlink/authlink/agent/cmd/app"
	"github.com/goauthlink/authlink/envoy"
	"github.com/spf13/cobra"
)

var grpcAddr string

type EnvoyExtension struct{}

func NewEnvoyExtension() *EnvoyExtension {
	return &EnvoyExtension{}
}

func (r *EnvoyExtension) ConfigRunCmd(cmd *cobra.Command) {
	cmd.Flags().StringVar(&grpcAddr, "envoy-grpc-addr", ":8282", "set listening address of the envoy grpc server (e.g., [ip]:<port>)")
}

func (r *EnvoyExtension) Server(runArgs []string, agent *agent.Agent) (agent.Server, error) {
	envoyServer, err := envoy.New(grpcAddr, agent.Policy(), envoy.WithLogger(agent.Logger()))
	if err != nil {
		return nil, fmt.Errorf("start envoy server: %w", err)
	}

	return envoyServer, nil
}

func main() {
	if err := app.NewRootCommand(NewEnvoyExtension()).Execute(); err != nil {
		println(err.Error())
		os.Exit(1)
	}
}
