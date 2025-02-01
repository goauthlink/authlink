// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"fmt"
	"log/slog"

	"github.com/goauthlink/authlink/controller/kube"
	"github.com/goauthlink/authlink/pkg/runtime"
)

type Controller struct {
	Id      string
	api     *kube.Api
	runtime *runtime.Runtime
	logger  *slog.Logger
}

func Init(config Config) (*Controller, error) {
	logger := slog.Default()

	kubeapi, err := kube.NewApi(config.Kubeconfig, logger)
	if err != nil {
		return nil, fmt.Errorf("error building kubeconfig: %w", err)
	}

	discoverServer, err := newDiscoveryServer(config, logger, kubeapi)
	if err != nil {
		return nil, fmt.Errorf("init discovery server: %w", err)
	}

	httpServer, err := NewHttpServer(config, WithLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("init http server: %w", err)
	}

	controller := &Controller{
		api:    kubeapi,
		logger: logger,
		runtime: runtime.NewRuntime([]runtime.Server{
			discoverServer,
			httpServer,
		}, logger),
	}

	return controller, nil
}

func (c *Controller) Start() {
	c.runtime.Start()
}
