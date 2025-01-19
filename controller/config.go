// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"log/slog"

	"github.com/goauthlink/authlink/pkg"
)

type SidecarResources struct {
	Limits *struct {
		Cpu    *string
		Memory *string
	}
	Requests *struct {
		Cpu    *string
		Memory *string
	}
}

type InectionConfig struct {
	Name          string
	Image         string
	PullPolicy    string
	HttpPort      int32
	GrpcPort      int32
	Args          []string
	Resources     *SidecarResources
	ConfigMapName string
}

type Config struct {
	Addr            string
	LogLevel        slog.Level
	DiscoveryAddr   string
	Kubeconfig      string
	InjectionConfig InectionConfig
}

func DefaultConfig() Config {
	return Config{
		Addr:          ":8181",
		LogLevel:      slog.LevelInfo,
		DiscoveryAddr: ":9191",
		Kubeconfig:    "",
		InjectionConfig: InectionConfig{
			Name:       "auth",
			Image:      pkg.AgentImageName + ":" + pkg.Version,
			PullPolicy: "IfNotPresent",
			HttpPort:   8181,
			GrpcPort:   8282,
			Args: []string{
				"run",
				"--tls-disable",
				"/policy.yaml",
			},
			ConfigMapName: "auth-policy",
		},
	}
}
