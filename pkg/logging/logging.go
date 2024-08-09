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
