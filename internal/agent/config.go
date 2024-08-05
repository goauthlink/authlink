package agent

import "log/slog"

type Config struct {
	Addr     string
	LogLevel slog.Level
	Policy   []byte
	Data     []byte
}

func DefaultConfig() Config {
	return Config{
		Addr:     ":8080",
		LogLevel: slog.LevelInfo,
		Policy:   []byte{},
		Data:     []byte{},
	}
}

func (c *Config) Validate(logger *slog.Logger) error {
	return nil
}
