// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/goauthlink/authlink/test/testdata"
	"github.com/goauthlink/authlink/test/util"
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

	agent, err := Init(config)
	if err != nil {
		t.Fatal(err)
	}

	checkerD := agent.policy.Data()
	if !reflect.DeepEqual(map[string]interface{}{"users": []interface{}{"user1", "user2"}}, checkerD) {
		t.Errorf("unexpected data, got %v", checkerD)
	}
}

func Test_InitNoData(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	config := DefaultConfig()
	config.LogLevel = slog.LevelError
	config.PolicyFilePath = rootDir + "/policy.yaml"

	agent, err := Init(config)
	if err != nil {
		t.Fatal(err)
	}

	if agent.policy.Data() != nil {
		t.Errorf("unexpected data, got %v", agent.policy.Data())
	}
}

func Test_TLSListening(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	config := DefaultConfig()
	config.PolicyFilePath = rootDir + "/policy.yaml"

	serverCert, err := tls.LoadX509KeyPair(rootDir+"/server.crt", rootDir+"/server.key")
	if err != nil {
		t.Fatal(err)
	}
	config.TLSCert = &serverCert
	config.LogLevel = slog.LevelError

	agent, err := Init(config)
	if err != nil {
		t.Fatal(err)
	}

	agentWg := sync.WaitGroup{}
	agentWg.Add(1)
	go func() {
		err = agent.Run()
		agentWg.Done()
	}()
	time.Sleep(time.Second * 1)

	clientCert, err := tls.LoadX509KeyPair(rootDir+"/client.crt", rootDir+"/client.key")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(testdata.TLSCACert)
	client := http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		},
	}, Timeout: 5 * time.Second}
	request, err := http.NewRequest(http.MethodPost, "https://localhost:8181/check", nil)
	request.Header.Set("x-path", "/endpoint")
	request.Header.Set("x-method", "GET")
	request.Header.Set("x-source", "client")
	if err != nil {
		t.Fatal(err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != http.StatusOK {
		t.Errorf("unexpected status, got %v", response.StatusCode)
	}

	agent.runtime.Stop()
	agentWg.Wait()
}
