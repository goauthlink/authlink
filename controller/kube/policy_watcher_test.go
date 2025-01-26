// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/goauthlink/authlink/controller/apis/generated/clientset/versioned/fake"
	"github.com/goauthlink/authlink/controller/apis/policies/v1beta1"
	"github.com/goauthlink/authlink/controller/models"
	"github.com/goauthlink/authlink/pkg/logging"
	sdk "github.com/goauthlink/authlink/sdk/policy"
	"gopkg.in/yaml.v3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var testPolicyConfig = `
cn:
  - header: "x-source1"
policies:
  - uri: ["/"]
    allow: ["*"]`

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
	api, clientSet := newFakeApi(logger)

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

	go func() {
		if err := watcher.Start(ctx); err != nil {
			t.Error(err)
		}
	}()

	expectedPolicy1 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{"l1": "v1"},
	})

	expectedPolicy2 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{"l1": "v1"},
	})

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %d", len(listener.received))
		t.Logf("%v", listener.received)
	}

	assertReceived(t, []NsPolicySnapshot{
		{
			policies: []models.Policy{expectedPolicy1},
		},
		{
			policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
	}, listener.received)
}

func Test_WatcherDelete(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := newFakeApi(logger)

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

	go func() {
		if err := watcher.Start(ctx); err != nil {
			t.Error(err)
		}
	}()

	expectedPolicy1 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	expectedPolicy2 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	fakeApiDeletePolicy(t, clientSet, "ns-1", "policy-1")

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %d", len(listener.received))
		t.Logf("%v", listener.received)
	}

	assertReceived(t, []NsPolicySnapshot{
		{
			policies: []models.Policy{expectedPolicy1},
		},
		{
			policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
		{
			policies: []models.Policy{expectedPolicy2},
		},
	}, listener.received)
}

func Test_WatcherLabels(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := newFakeApi(logger)

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

	go func() {
		if err := watcher.Start(ctx); err != nil {
			t.Error(err)
		}
	}()

	expectedPolicy1 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{"l1": "v1"},
	})

	expectedPolicy2 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{"l2": "v2"},
	})

	fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-3",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{"l1": "v1", "l2": "v2", "l3": "v3"},
	})

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %d", len(listener.received))
		t.Logf("%v", listener.received)
	}

	assertReceived(t, []NsPolicySnapshot{
		{
			policies: []models.Policy{expectedPolicy1},
		},
		{
			policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
		{
			policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
	}, listener.received)
}

func Test_WatcherNamespace(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := newFakeApi(logger)

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

	go func() {
		if err := watcher.Start(ctx); err != nil {
			t.Error(err)
		}
	}()

	expectedPolicy1 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	expectedPolicy2 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: "ns-1",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	expectedPolicy3 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-3",
		Namespace: "ns-2",
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	lsWaitGroup := sync.WaitGroup{}
	lsWaitGroup.Add(2)

	go func() {
		defer lsWaitGroup.Done()
		if !listener1.waitToRecieve(time.Second * 3) {
			t.Errorf("waiting listener events canceled by timeout, received %d", len(listener1.received))
			t.Logf("%v", listener1.received)
		}

		assertReceived(t, []NsPolicySnapshot{
			{
				policies: []models.Policy{expectedPolicy1},
			},
			{
				policies: []models.Policy{expectedPolicy1, expectedPolicy2},
			},
		}, listener1.received)
	}()

	go func() {
		defer lsWaitGroup.Done()

		if !listener2.waitToRecieve(time.Second * 3) {
			t.Errorf("waiting listener events canceled by timeout, received %d", len(listener1.received))
			t.Logf("%v", listener1.received)
		}

		assertReceived(t, []NsPolicySnapshot{
			{
				policies: []models.Policy{expectedPolicy3},
			},
		}, listener2.received)
	}()

	lsWaitGroup.Wait()
}

func Test_WatcherUnsibscribe(t *testing.T) {
	logger := logging.NewNullLogger()
	api, clientSet := newFakeApi(logger)

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

	go func() {
		if err := watcher.Start(ctx); err != nil {
			t.Error(err)
		}
	}()

	expectedPolicy1 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-1",
		Namespace: ns1,
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	expectedPolicy2 := fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-2",
		Namespace: ns1,
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	if !listener.waitToRecieve(time.Second * 3) {
		t.Errorf("waiting listener events canceled by timeout, received %d", len(listener.received))
		t.Logf("%v", listener.received)
	}

	watcher.Unsubscribe(ClientId{
		Name:      pod1,
		Namespace: ns1,
		Labels:    map[string]string{},
	})

	fakeApiCreatePolicy(t, clientSet, models.Policy{
		Name:      "policy-3",
		Namespace: ns1,
		Raw:       []byte(testPolicyConfig),
		Labels:    map[string]string{},
	})

	assertReceived(t, []NsPolicySnapshot{
		{
			policies: []models.Policy{expectedPolicy1},
		},
		{
			policies: []models.Policy{expectedPolicy1, expectedPolicy2},
		},
	}, listener.received)
}

func assertReceived(t *testing.T, expected []NsPolicySnapshot, actual []NsPolicySnapshot) {
	if len(actual[0].policies) > 0 {
		t.Errorf("the first received event must not contain policies, got %d", len(actual))
	}

	if len(actual)-1 != len(expected) {
		t.Errorf("expected %d events but got %d", len(expected), len(actual)-1)
	}

	received := actual[1:]

	for i := range expected {
		if len(expected[i].policies) != len(received[i].policies) {
			t.Errorf("snapshots are not equal, got %v", received)
			return
		}

		for j := range expected[i].policies {
			if !reflect.DeepEqual(expected[i].policies[j], received[i].policies[j]) {
				t.Errorf("snapshots are not equal: got index %d, policy index %d, snapshot %s, expected %s",
					i, j, received[i].policies[j], expected[i].policies[j])
				return
			}
		}
	}
}

func fakeApiDeletePolicy(t *testing.T, clientSet *fake.Clientset, ns, name string) {
	if err := clientSet.AuthlinkV1beta1().Policies(ns).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		t.Error(err)
	}
}

func fakeApiCreatePolicy(t *testing.T, clientSet *fake.Clientset, policy models.Policy) models.Policy {
	config := sdk.Config{}
	err := yaml.Unmarshal(policy.Raw, &config)
	if err != nil {
		t.Fatal(err)
	}

	configJson, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	_, err = clientSet.AuthlinkV1beta1().Policies(policy.Namespace).Create(context.Background(), &v1beta1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.Name,
		},
		Spec: v1beta1.PolicySpec{
			Config: config,
			Match: v1beta1.PolicyMatch{
				Labels: policy.Labels,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Error(err)
	}

	policy.Raw = configJson

	return policy
}
