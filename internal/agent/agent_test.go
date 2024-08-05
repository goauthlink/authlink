package agent

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InitData(t *testing.T) {
	data := `{"users":["user1","user2"]}`
	policy := `cn:
  - header: "x-source1"
policies:
  - uri: ["/endpoint"]
    allow: ["client"]`

	config := Config{
		LogLevel: slog.LevelError,
		Policy:   []byte(policy),
		Data:     []byte(data),
	}

	agent, err := Init(config)
	require.NoError(t, err)

	checkerD := agent.checker.Data()
	assert.Equal(t, map[string]interface{}{"users": []interface{}{"user1", "user2"}}, checkerD)
}

func Test_InitNoData(t *testing.T) {
	policy := `cn:
  - header: "x-source1"
policies:
  - uri: ["/endpoint"]
    allow: ["client"]`

	config := Config{
		LogLevel: slog.LevelError,
		Policy:   []byte(policy),
	}

	_, err := Init(config)
	require.NoError(t, err)
}
