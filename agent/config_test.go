package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArguments(t *testing.T) {
	cfg := DefaultConfig()

	cfg.UpdateFilesSeconds = -1

	err := cfg.Validate()
	assert.ErrorContains(t, err, errUpdatePolicyFileSeconds)
}
