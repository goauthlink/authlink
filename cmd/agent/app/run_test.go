// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package app

import (
	"log/slog"
	"testing"

	"github.com/auth-request-agent/agent/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestCmdParams() runCmdParams {
	return runCmdParams{
		logLevel: "info",
		addr:     ":8080",
	}
}

var (
	testCommonData   = `{"users":["user1","user2"]}`
	testCommonPolicy = `cn:
  - header: "x-source1"
policies:
  - uri: ["/endpoint"]
    allow: ["client"]`
)

func createFiles(t *testing.T) (string, func()) {
	rootDir, cleanFs, err := util.MakeTmpFs("", t.Name(), map[string][]byte{
		"policy.yaml": []byte(testCommonPolicy),
		"data.json":   []byte(testCommonData),
		"data.txt":    []byte("text"),
	})
	if err != nil {
		t.Fatal(err)
	}

	return rootDir, cleanFs
}

func Test_AgentOtherParams(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	params := createTestCmdParams()
	params.updateFilesSeconds = 60
	params.monitoringAddr = ":8181"
	params.logCheckResults = true

	config, err := prepareConfig([]string{rootDir + "/policy.yaml"}, params)
	require.NoError(t, err)

	assert.Equal(t, params.updateFilesSeconds, config.UpdateFilesSeconds)
	assert.Equal(t, params.monitoringAddr, config.MonitoringAddr)
	assert.Equal(t, params.logCheckResults, true)
}

func Test_AgentLogLevel(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	params := createTestCmdParams()
	params.logLevel = "debug"

	config, err := prepareConfig([]string{rootDir + "/policy.yaml"}, params)
	require.NoError(t, err)

	assert.Equal(t, slog.LevelDebug, config.LogLevel)
}

func Test_AgentArgsPolicyAndData(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	policyFilePath := rootDir + "/policy.yaml"
	dataFilePath := rootDir + "/data.json"

	// ---
	config, err := prepareConfig([]string{policyFilePath, dataFilePath}, createTestCmdParams())
	require.NoError(t, err)

	assert.Equal(t, policyFilePath, config.PolicyFilePath)
	assert.Equal(t, dataFilePath, config.DataFilePath)

	// ---
	config, err = prepareConfig([]string{dataFilePath, policyFilePath}, createTestCmdParams())
	require.NoError(t, err)

	assert.Equal(t, dataFilePath, config.DataFilePath)
	assert.Equal(t, policyFilePath, config.PolicyFilePath)

	// ---
	config, err = prepareConfig([]string{policyFilePath}, createTestCmdParams())
	require.NoError(t, err)
	assert.Equal(t, policyFilePath, config.PolicyFilePath)
	assert.Equal(t, "", config.DataFilePath)

	// ---
	_, err = prepareConfig([]string{}, createTestCmdParams())
	require.ErrorContains(t, err, usageArgs)
}
