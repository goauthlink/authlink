// Copyright 2024 The AuthPolicyController Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logging

import (
	"fmt"
	"log/slog"
)

func ParseLevel(s string) (slog.Level, error) {
	var lvl slog.Level
	err := lvl.UnmarshalText([]byte(s))
	if err != nil {
		return 0, fmt.Errorf("fail to parse log level: %s: %w", s, err)
	}

	return lvl, nil
}

type logNullWriter struct{}

func (logNullWriter) Write([]byte) (int, error) { return 0, nil }

func NewNullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(logNullWriter{}, nil))
}
