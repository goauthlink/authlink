// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/auth-request-agent/agent/sdk/policy"
)

type CheckLogger struct {
	logger *slog.Logger
}

func NewCheckLogger(logger *slog.Logger) *CheckLogger {
	return &CheckLogger{logger: logger}
}

func NewNullCheckLogger() *CheckLogger {
	nullLogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	return &CheckLogger{logger: nullLogger}
}

func (cl *CheckLogger) Log(in policy.CheckInput, result policy.CheckResult) {
	if result.Err == nil {
		cl.logger.Info(fmt.Sprintf("Check result [OK] - allowed: %t, client name: '%s', matched endpoint: '%s', input uri: '%s', input method: '%s'",
			result.Allow,
			result.ClientName,
			result.Endpoint,
			in.Uri,
			in.Method,
		))
	} else {
		cl.logger.Info(fmt.Sprintf("Check result [ERR] - '%s', client name: '%s', matched endpoint: '%s', input uri: '%s', input method: '%s'",
			result.Err.Error(),
			result.ClientName,
			result.Endpoint,
			in.Uri,
			in.Method,
		))
	}
}
