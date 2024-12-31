// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"crypto/tls"
	"errors"
	"log/slog"
)

type Config struct {
	HttpAddr           string
	MonitoringAddr     string
	LogLevel           slog.Level
	LogCheckResults    bool
	PolicyFilePath     string
	DataFilePath       string
	UpdateFilesSeconds int
	TLSCert            *tls.Certificate
}

func DefaultConfig() Config {
	return Config{
		HttpAddr:           ":8181",
		MonitoringAddr:     ":9191",
		LogLevel:           slog.LevelInfo,
		LogCheckResults:    false,
		UpdateFilesSeconds: 0,
		PolicyFilePath:     "policy.yaml",
		DataFilePath:       "",
	}
}

const (
	errUpdatePolicyFileSeconds     = "update policy file period must not be less than 0 seconds"
	errTLSPrivateKeyPathIsRequired = "TLS private key is required when TLS is enabled"
	errTLSCertPathIsRequired       = "TLS certificate is required when TLS is enabled"
)

func (c *Config) Validate() error {
	if c.UpdateFilesSeconds < 0 {
		return errors.New(errUpdatePolicyFileSeconds)
	}

	return nil
}
