// Copyright 2024 The AuthPolicyController Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"fmt"
	"log/slog"
)

type Config struct {
	Addr               string
	MonitoringAddr     string
	LogLevel           slog.Level
	PolicyFilePath     string
	DataFilePath       string
	UpdateFilesSeconds int
}

func DefaultConfig() Config {
	return Config{
		Addr:               ":8080",
		MonitoringAddr:     ":9191",
		LogLevel:           slog.LevelInfo,
		UpdateFilesSeconds: 0,
		PolicyFilePath:     "policy.yaml",
		DataFilePath:       "",
	}
}

const (
	errUpdatePolicyFileSeconds = "update policy file period must not be less than 0 seconds"
)

func (c *Config) Validate() error {
	if c.UpdateFilesSeconds < 0 {
		return fmt.Errorf(errUpdatePolicyFileSeconds)
	}

	return nil
}
