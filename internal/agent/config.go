package agent

import "log/slog"

type Config struct {
	Addr       string
	LogLevel   slog.Level
	PolicyFile string
}

func DefaultConfig() Config {
	return Config{
		Addr:       ":8080",
		LogLevel:   slog.LevelInfo,
		PolicyFile: "policy.yaml",
	}
}

func (c *Config) Validate(logger *slog.Logger) error {
	return nil
}
