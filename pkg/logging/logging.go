// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logging

import (
	"fmt"
	"io"
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

func NewNullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
