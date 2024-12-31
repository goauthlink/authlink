package main

import (
	"fmt"

	"github.com/auth-request-agent/agent/agent"
	"github.com/auth-request-agent/agent/envoy"
	"github.com/spf13/cobra"
)

var grpcAddr string

type EnvoyExtension struct{}

func NewEnvoyExtension() *EnvoyExtension {
	return &EnvoyExtension{}
}

func (r *EnvoyExtension) ConfigRunCmd(cmd *cobra.Command) {
	cmd.Flags().StringVar(&grpcAddr, "envoy-grpc-addr", ":9292", "set listening address of the envoy grpc server (e.g., [ip]:<port>)")
}

func (r *EnvoyExtension) Server(runArgs []string, agent *agent.Agent) (agent.Server, error) {
	envoyServer, err := envoy.New(grpcAddr, agent.Policy(), envoy.WithLogger(agent.Logger()))
	if err != nil {
		return nil, fmt.Errorf("start envoy server: %w", err)
	}

	return envoyServer, nil
}
