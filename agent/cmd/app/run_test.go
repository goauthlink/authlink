package app

import (
	"log/slog"
	"testing"

	"github.com/auth-policy-controller/apc/test/util"
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

	// ---
	config, err := prepareConfig([]string{rootDir + "/policy.yaml", rootDir + "/data.json"}, createTestCmdParams())
	require.NoError(t, err)

	assert.Equal(t, []byte(testCommonPolicy), config.Policy)
	assert.Equal(t, []byte(testCommonData), config.Data)

	// ---
	config, err = prepareConfig([]string{rootDir + "/data.json", rootDir + "/policy.yaml"}, createTestCmdParams())
	require.NoError(t, err)

	assert.Equal(t, []byte(testCommonPolicy), config.Policy)
	assert.Equal(t, []byte(testCommonData), config.Data)

	// ---
	config, err = prepareConfig([]string{rootDir + "/policy.yaml"}, createTestCmdParams())
	require.NoError(t, err)
	assert.Equal(t, []byte(testCommonPolicy), config.Policy)
	assert.Equal(t, []byte{}, config.Data)

	// ---
	_, err = prepareConfig([]string{rootDir + "/data.json"}, createTestCmdParams())
	require.ErrorContains(t, err, usageArgs)

	// ---
	_, err = prepareConfig([]string{}, createTestCmdParams())
	require.ErrorContains(t, err, usageArgs)
}
