// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/auth-request-agent/agent/test/testdata"
	"github.com/auth-request-agent/agent/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testData   = `{"users":["user1","user2"]}`
	testPolicy = `cn:
  - header: "x-source"
policies:
  - uri: ["/endpoint"]
    allow: ["client"]`
)

func createFiles(t *testing.T) (string, func()) {
	rootDir, cleanFs, err := util.MakeTmpFs("", t.Name(), map[string][]byte{
		"policy.yaml": []byte(testPolicy),
		"data.json":   []byte(testData),
		"data.txt":    []byte("text"),
		"server.key":  testdata.TLSServerKey,
		"server.crt":  testdata.TLSServerCert,
		"client.key":  testdata.TLSClientKey,
		"client.crt":  testdata.TLSClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}

	return rootDir, cleanFs
}

func Test_InitFiles(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	config := DefaultConfig()
	config.LogLevel = slog.LevelError
	config.DataFilePath = rootDir + "/data.json"
	config.PolicyFilePath = rootDir + "/policy.yaml"

	agent, err := InitNewAgent(config)
	require.NoError(t, err)

	checkerD := agent.checker.Data()

	assert.Equal(t, map[string]interface{}{"users": []interface{}{"user1", "user2"}}, checkerD)
}

func Test_InitNoData(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	config := DefaultConfig()
	config.LogLevel = slog.LevelError
	config.PolicyFilePath = rootDir + "/policy.yaml"

	agent, err := InitNewAgent(config)
	require.NoError(t, err)

	assert.Equal(t, nil, agent.checker.Data())
}

func Test_TLSListening(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	config := DefaultConfig()
	config.PolicyFilePath = rootDir + "/policy.yaml"
	config.LogLevel = slog.LevelError

	serverCert, err := tls.LoadX509KeyPair(rootDir+"/server.crt", rootDir+"/server.key")
	require.NoError(t, err)
	config.TLSCert = &serverCert
	config.LogLevel = slog.LevelError

	agent, err := InitNewAgent(config)
	require.NoError(t, err)

	stop := make(chan struct{}, 1)
	go func() {
		err = agent.Run(stop)
	}()
	defer func() {
		stop <- struct{}{}
	}()
	time.Sleep(time.Second * 1)

	clientCert, err := tls.LoadX509KeyPair(rootDir+"/client.crt", rootDir+"/client.key")
	require.NoError(t, err)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(testdata.TLSCACert)
	client := http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		},
	}, Timeout: 5 * time.Second}
	request, err := http.NewRequest(http.MethodPost, "https://localhost:8080/check", nil)
	request.Header.Set("x-path", "/endpoint")
	request.Header.Set("x-method", "GET")
	request.Header.Set("x-source", "client")
	require.NoError(t, err)

	response, err := client.Do(request)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func Test_UpdateFiles(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	config := DefaultConfig()
	config.PolicyFilePath = rootDir + "/policy.yaml"
	config.LogLevel = slog.LevelError
	config.UpdateFilesSeconds = 1

	agent, err := InitNewAgent(config)
	require.NoError(t, err)

	stop := make(chan struct{}, 1)
	go func() {
		err = agent.Run(stop)
	}()
	time.Sleep(time.Second * 1)

	assert.Equal(t, []byte(testPolicy), agent.checker.Policy())

	newPolicy := `cn:
  - header: "x-source2"
policies:
  - uri: ["/endpoint2"]
    allow: ["client2"]`

	require.NoError(t, util.ReWriteFileContent(rootDir+"/policy.yaml", []byte(newPolicy)))

	time.Sleep(time.Second * 3)

	assert.Equal(t, []byte(newPolicy), agent.checker.Policy())

	stop <- struct{}{}

	require.NoError(t, err)
}
