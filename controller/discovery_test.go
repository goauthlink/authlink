// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/goauthlink/authlink/api"
	versionedFake "github.com/goauthlink/authlink/controller/apis/generated/clientset/versioned/fake"
	"github.com/goauthlink/authlink/controller/kube"
	"github.com/goauthlink/authlink/controller/kube/fake"
	"github.com/goauthlink/authlink/controller/models"
	"github.com/goauthlink/authlink/pkg/logging"
	"github.com/goauthlink/authlink/sdk/policy"
	"google.golang.org/grpc/metadata"
)

type mockStream struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newMockStream() mockStream {
	ctx, cancel := context.WithCancel(context.Background())
	return mockStream{ctx, cancel}
}

func (ms mockStream) Context() context.Context    { return ms.ctx }
func (ms mockStream) SendMsg(m interface{}) error { return nil }
func (ms mockStream) RecvMsg(m interface{}) error { return nil }

type mockServerStream struct{ mockStream }

func NewMockServerStream() mockServerStream {
	return mockServerStream{newMockStream()}
}

func (mss mockServerStream) SetHeader(metadata.MD) error  { return nil }
func (mss mockServerStream) SendHeader(metadata.MD) error { return nil }
func (mss mockServerStream) SetTrailer(metadata.MD)       {}

type bufferingPolicyStream struct {
	updates  []*api.PolicySnapshot
	expected int
	done     chan bool
	mockServerStream
}

func newBuffergingPolicyStream(expected int) *bufferingPolicyStream {
	return &bufferingPolicyStream{
		updates:          []*api.PolicySnapshot{},
		expected:         expected,
		done:             make(chan bool, 1),
		mockServerStream: NewMockServerStream(),
	}
}

func (bgs *bufferingPolicyStream) Send(update *api.PolicySnapshot) error {
	bgs.updates = append(bgs.updates, update)
	if bgs.expected > 0 && len(bgs.updates) >= bgs.expected {
		close(bgs.done)
	}
	return nil
}

func (bgs *bufferingPolicyStream) waitToRecieve(timeout time.Duration) bool {
	if len(bgs.updates) >= bgs.expected {
		return true
	}

	timer := time.NewTimer(timeout)
	for {
		select {
		case <-timer.C:
			return false
		case <-bgs.done:
			return true
		}
	}
}

func makeTestServer(t *testing.T) (*discoveryServer, *versionedFake.Clientset) {
	logger := logging.NewNullLogger()
	kubeapi, clientSet := kube.NewFakeApi(logger)

	config := DefaultConfig()
	server, err := newDiscoveryServer(config, logger, kubeapi)
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := context.WithCancel(context.Background())
	server.ctx = ctx

	err = kubeapi.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	return server, clientSet
}

func Test_GetPolicyStream(t *testing.T) {
	server, clientSet := makeTestServer(t)
	stream := newBuffergingPolicyStream(3)
	defer stream.cancel()

	go func() {
		if err := server.Policy(&api.GetPolicy{
			Id:        "pod-1",
			Namespace: "ns-1",
			Labels:    map[string]string{},
		}, stream); err != nil {
			t.Error(err)
		}
	}()

	testPolicy := policy.Config{
		Cn:       []policy.Cn{},
		Vars:     map[string][]string{},
		Default:  []string{},
		Policies: []policy.Policy{},
	}

	fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Config:    testPolicy,
		Labels:    map[string]string{},
	})

	fake.DeletePolicy(t, clientSet, "ns-1", "policy-1")

	if !stream.waitToRecieve(time.Second * 3) {
		t.Errorf("expected %d but got %d responses in stream", 3, len(stream.updates))
	}

	testPolicyJson, err := json.Marshal(testPolicy)
	if err != nil {
		t.Fatal(err)
	}

	assertSnapshotsAreEqual(t, []*api.PolicySnapshot{
		{
			Policy: []string{},
		},
		{
			Policy: []string{string(testPolicyJson)},
		},
		{
			Policy: []string{},
		},
	}, stream.updates)
}

func Test_GetPolicyCancelStream(t *testing.T) {
	server, clientSet := makeTestServer(t)
	stream := newBuffergingPolicyStream(2)
	defer stream.cancel()

	endStream := make(chan bool)
	go func() {
		defer close(endStream)
		if err := server.Policy(&api.GetPolicy{
			Id:        "pod-1",
			Namespace: "ns-1",
			Labels:    map[string]string{},
		}, stream); err != nil {
			t.Error(err)
		}
	}()

	testPolicy := policy.Config{
		Cn:       []policy.Cn{},
		Vars:     map[string][]string{},
		Default:  []string{},
		Policies: []policy.Policy{},
	}

	fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Config:    testPolicy,
		Labels:    map[string]string{},
	})

	time.Sleep(time.Second * 2)
	stream.cancel()
	<-endStream

	fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Config:    testPolicy,
		Labels:    map[string]string{},
	})

	if !stream.waitToRecieve(time.Second * 3) {
		t.Errorf("expected %d but got %d responses in stream", 2, len(stream.updates))
	}

	testPolicyJson, err := json.Marshal(testPolicy)
	if err != nil {
		t.Fatal(err)
	}

	assertSnapshotsAreEqual(t, []*api.PolicySnapshot{
		{
			Policy: []string{},
		},
		{
			Policy: []string{string(testPolicyJson)},
		},
	}, stream.updates)
}

func assertSnapshotsAreEqual(t *testing.T, expected []*api.PolicySnapshot, actual []*api.PolicySnapshot) {
	t.Helper()

	if len(actual) != len(expected) {
		t.Errorf("expected %d events but got %d", len(expected), len(actual))
	}

	for i := range expected {
		if !reflect.DeepEqual(expected[i].Policy, actual[i].Policy) {
			t.Errorf("snapshots are not equal: got %v", actual)
		}
	}
}
