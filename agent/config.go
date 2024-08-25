package agent

import (
	"fmt"
	"log/slog"
)

type Config struct {
	Addr               string
	LogLevel           slog.Level
	PolicyFilePath     string
	DataFilePath       string
	UpdateFilesSeconds int
}

func DefaultConfig() Config {
	return Config{
		Addr:               ":8080",
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
