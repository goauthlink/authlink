// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/goauthlink/authlink/controller/kube/fake"
	"github.com/goauthlink/authlink/controller/models"
	"github.com/goauthlink/authlink/pkg/logging"
	"github.com/goauthlink/authlink/sdk/policy"
)

var testPolicyConfig = policy.Config{
	Cn: []policy.Cn{{
		Prefix: "prefix",
		Header: new(string),
		JWT:    &policy.CnJWT{},
	}},
	Vars:     map[string][]string{},
	Default:  []string{"*"},
	Policies: []policy.Policy{},
}

type mockPolicyListener struct {
	received []NsPolicySnapshot
	expected int
	done     chan bool
}

func newMockPolicyListener(expected int) *mockPolicyListener {
	return &mockPolicyListener{
		received: []NsPolicySnapshot{},
		expected: expected,
		done:     make(chan bool, 1),
	}
}

func (mpl *mockPolicyListener) Update(snapshot NsPolicySnapshot) {
	mpl.received = append(mpl.received, snapshot)
	if mpl.expected > 0 && len(mpl.received) >= mpl.expected {
		close(mpl.done)
	}
}

func (mpl *mockPolicyListener) waitToRecieve(timeout time.Duration) bool {
	if len(mpl.received) >= mpl.expected {
		return true
	}

	timer := time.NewTimer(timeout)
	for {
		select {
		case <-timer.C:
			return false
		case <-mpl.done:
			return true
		}
	}
}

func Test_WatcherAdd(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := NewFakeApi(logger)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	err := api.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}

	watcher, err := NewPolicyWatcher(logger, api)
	if err != nil {
		t.Fatal(err)
	}

	listener := newMockPolicyListener(3)
	watcher.Subscribe(ClientId{
		Name:      "pod-1",
		Namespace: "ns-1",
		Labels:    map[string]string{"l1": "v1"},
	}, listener)

	expectedPolicy1 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{"l1": "v1"},
	})

	expectedPolicy2 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{"l1": "v1"},
	})

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %v", listener.received)
	}

	assertReceived(t, []NsPolicySnapshot{
		{
			Policies: []models.Policy{expectedPolicy1},
		},
		{
			Policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
	}, listener.received)
}

func Test_WatcherDelete(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := NewFakeApi(logger)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	err := api.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}

	watcher, err := NewPolicyWatcher(logger, api)
	if err != nil {
		t.Fatal(err)
	}

	listener := newMockPolicyListener(4)
	watcher.Subscribe(ClientId{
		Name:      "pod-1",
		Namespace: "ns-1",
		Labels:    map[string]string{},
	}, listener)

	expectedPolicy1 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	expectedPolicy2 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	fake.DeletePolicy(t, clientSet, "ns-1", "policy-1")

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %v", listener.received)
	}

	assertReceived(t, []NsPolicySnapshot{
		{
			Policies: []models.Policy{expectedPolicy1},
		},
		{
			Policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
		{
			Policies: []models.Policy{expectedPolicy2},
		},
	}, listener.received)
}

func Test_WatcherLabels(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := NewFakeApi(logger)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	err := api.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}

	watcher, err := NewPolicyWatcher(logger, api)
	if err != nil {
		t.Fatal(err)
	}

	listener := newMockPolicyListener(4)
	watcher.Subscribe(ClientId{
		Name:      "pod-1",
		Namespace: "ns-1",
		Labels:    map[string]string{"l1": "v1", "l2": "v2"},
	}, listener)

	expectedPolicy1 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{"l1": "v1"},
	})

	expectedPolicy2 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{"l2": "v2"},
	})

	fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-3",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{"l1": "v1", "l2": "v2", "l3": "v3"},
	})

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %v", listener.received)
	}

	assertReceived(t, []NsPolicySnapshot{
		{
			Policies: []models.Policy{expectedPolicy1},
		},
		{
			Policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
		{
			Policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
	}, listener.received)
}

func Test_WatcherNamespace(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := NewFakeApi(logger)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	err := api.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}

	watcher, err := NewPolicyWatcher(logger, api)
	if err != nil {
		t.Fatal(err)
	}

	listener1 := newMockPolicyListener(3)
	watcher.Subscribe(ClientId{
		Name:      "pod-1",
		Namespace: "ns-1",
		Labels:    map[string]string{},
	}, listener1)

	listener2 := newMockPolicyListener(2)
	watcher.Subscribe(ClientId{
		Name:      "pod-1",
		Namespace: "ns-2",
		Labels:    map[string]string{},
	}, listener2)

	expectedPolicy1 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	expectedPolicy2 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	expectedPolicy3 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-3",
		Namespace: "ns-2",
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	lsWaitGroup := sync.WaitGroup{}
	lsWaitGroup.Add(2)

	go func() {
		defer lsWaitGroup.Done()
		if !listener1.waitToRecieve(time.Second * 3) {
			t.Errorf("waiting listener events canceled by timeout, received %v", listener1.received)
		}

		assertReceived(t, []NsPolicySnapshot{
			{
				Policies: []models.Policy{expectedPolicy1},
			},
			{
				Policies: []models.Policy{expectedPolicy1, expectedPolicy2},
			},
		}, listener1.received)
	}()

	go func() {
		defer lsWaitGroup.Done()

		if !listener2.waitToRecieve(time.Second * 3) {
			t.Errorf("waiting listener events canceled by timeout, received %v", listener2.received)
		}

		assertReceived(t, []NsPolicySnapshot{
			{
				Policies: []models.Policy{expectedPolicy3},
			},
		}, listener2.received)
	}()

	lsWaitGroup.Wait()
}

func Test_WatcherUnsibscribe(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := NewFakeApi(logger)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	err := api.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}

	watcher, err := NewPolicyWatcher(logger, api)
	if err != nil {
		t.Fatal(err)
	}

	const (
		ns1  = "ns-1"
		pod1 = "pod-1"
	)

	listener := newMockPolicyListener(3)
	watcher.Subscribe(ClientId{
		Name:      pod1,
		Namespace: ns1,
		Labels:    map[string]string{},
	}, listener)

	expectedPolicy1 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: ns1,
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	expectedPolicy2 := fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: ns1,
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %v", listener.received)
	}

	watcher.Unsubscribe(ClientId{
		Name:      pod1,
		Namespace: ns1,
		Labels:    map[string]string{},
	})

	fake.CreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-3",
		Namespace: ns1,
		Config:    testPolicyConfig,
		Labels:    map[string]string{},
	})

	assertReceived(t, []NsPolicySnapshot{
		{
			Policies: []models.Policy{expectedPolicy1},
		},
		{
			Policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
	}, listener.received)
}

func assertReceived(t *testing.T, expected []NsPolicySnapshot, actual []NsPolicySnapshot) {
	t.Helper()
	if len(actual[0].Policies) > 0 {
		t.Errorf("the first received event must not contain policies, got %d", len(actual))
		return
	}

	if len(actual)-1 != len(expected) {
		t.Errorf("expected %d events but got %d", len(expected), len(actual)-1)
	}

	received := actual[1:]
	sortPolicySnapshot(received)
	sortPolicySnapshot(expected)
	if !reflect.DeepEqual(received, expected) {
		t.Errorf("snapshots are not equal: got %v", received)
	}
}

func sortPolicySnapshot(snapshots []NsPolicySnapshot) {
	for si := range snapshots {
		slices.SortFunc[[]models.Policy](snapshots[si].Policies, func(a models.Policy, b models.Policy) int {
			if a.Name == b.Name {
				return 0
			}
			if a.Name < b.Name {
				return -1
			}
			return 1
		})
	}
}
