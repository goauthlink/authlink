// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package run

import (
	"log/slog"
	"testing"

	"github.com/goauthlink/authlink/test/testdata"
	"github.com/goauthlink/authlink/test/util"
)

func createTestCmdParams() runCmdParams {
	return runCmdParams{
		logLevel:   "info",
		httpAddr:   ":8181",
		tlsDisable: true,
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
		"key.pem":     testdata.TLSServerKey,
		"cert.pem":    testdata.TLSServerCert,
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
	params.monitoringAddr = ":8181"
	params.logCheckResults = true
	params.policyFilePath = rootDir + "/policy.yaml"

	config, err := prepareConfig(params)
	if err != nil {
		t.Fatal(err)
	}

	if config.MonitoringAddr != params.monitoringAddr {
		t.Errorf("monitoring-addr, expected %s, got %s", params.monitoringAddr, config.MonitoringAddr)
	}
	if config.LogCheckResults != params.logCheckResults {
		t.Errorf("log-check-results, expected %t, got %t", params.logCheckResults, config.LogCheckResults)
	}
}

func Test_AgentTLSParams(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	params := createTestCmdParams()
	params.tlsDisable = true
	params.policyFilePath = rootDir + "/policy.yaml"

	config, err := prepareConfig(params)
	if err != nil {
		t.Fatal(err)
	}
	if config.TLSCert != nil {
		t.Error("config tls cert must be nil")
	}

	// ---

	params = createTestCmdParams()
	params.tlsDisable = false
	params.tlsCertPath = rootDir + "/cert.pem"
	params.tlsPrivateKeyPath = rootDir + "/key.pem"
	params.policyFilePath = rootDir + "/policy.yaml"

	config, err = prepareConfig(params)
	if err != nil {
		t.Fatal(err)
	}

	if config.TLSCert == nil {
		t.Error("config tls cert must be not nil")
	}
}

func Test_AgentLogLevel(t *testing.T) {
	rootDir, cleanFs := createFiles(t)
	defer cleanFs()

	params := createTestCmdParams()
	params.logLevel = "debug"
	params.policyFilePath = rootDir + "/policy.yaml"

	config, err := prepareConfig(params)
	if err != nil {
		t.Fatal(err)
	}

	if config.LogLevel != slog.LevelDebug {
		t.Errorf("expected log level %s, got %s", slog.LevelDebug, config.LogLevel)
	}
}

func Test_AgentPolicyDataOrDiscovery(t *testing.T) {
	t.Run("discovery-addr or policy-file", func(t *testing.T) {
		params := createTestCmdParams()
		params.policyFilePath = "/policy.yaml"
		params.dataFilePath = "/data.json"
		params.discoveryAddr = "service"

		_, err := prepareConfig(params)
		if err == nil || err.Error() != "it is possible to use only -discovery-addr or -policy-file/-data-file at the same time" {
			t.Errorf("expected error, got '%v'", err)
		}
	})

	t.Run("without discovery-addr and policy-file", func(t *testing.T) {
		params := createTestCmdParams()

		_, err := prepareConfig(params)
		if err == nil || err.Error() != "-discovery-addr or -policy-file are required for policy loading" {
			t.Errorf("expected error, got '%v'", err)
		}
	})

	t.Run("discovery-addr without policy-file", func(t *testing.T) {
		params := createTestCmdParams()
		params.discoveryAddr = "service"

		_, err := prepareConfig(params)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("policy-file without discovery-addr", func(t *testing.T) {
		params := createTestCmdParams()
		params.policyFilePath = "/policy.yaml"

		_, err := prepareConfig(params)
		if err != nil {
			t.Fatal(err)
		}
	})
}
