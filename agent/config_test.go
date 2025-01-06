// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

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
