// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"k8s.io/client-go/tools/cache"

	"github.com/goauthlink/authlink/controller/apis/policies/v1beta1"
	"github.com/goauthlink/authlink/controller/models"
	"github.com/goauthlink/authlink/pkg/queue"
)

const (
	eventAddOp = iota
	eventUpdateOp
	eventDeleteOp
)

type (
	eventOp int

	kubePolicyEvent struct {
		policy models.Policy
		op     eventOp
	}

	NsPolicySnapshot struct {
		policies []models.Policy
	}

	PolicyListener interface {
		Update(snapshot NsPolicySnapshot)
	}

	ClientId struct {
		Name      string
		Namespace string
		Labels    map[string]string
	}

	clientEventListener struct {
		clientId ClientId
		listener PolicyListener
	}
)

type PolicyWatcher struct {
	logger    *slog.Logger
	queue     *queue.Queue[kubePolicyEvent]
	listeners map[string][]clientEventListener
	lsMu      *sync.Mutex
	cache     *policyCache
}

func NewPolicyWatcher(logger *slog.Logger, api *Api) (*PolicyWatcher, error) {
	watcher := &PolicyWatcher{
		logger:    logger,
		queue:     queue.NewQueue[kubePolicyEvent](),
		listeners: map[string][]clientEventListener{},
		lsMu:      &sync.Mutex{},
		cache:     newPolicyCache(),
	}

	_, err := api.Policies().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    watcher.onAdd,
		UpdateFunc: watcher.onUpdate,
		DeleteFunc: watcher.onDelete,
	})
	if err != nil {
		return nil, err
	}

	return watcher, nil
}

func (w *PolicyWatcher) Subscribe(clientId ClientId, listener PolicyListener) error {
	w.lsMu.Lock()
	defer w.lsMu.Unlock()

	if _, exist := w.listeners[clientId.Namespace]; !exist {
		w.listeners[clientId.Namespace] = []clientEventListener{}
	}

	for _, cel := range w.listeners[clientId.Namespace] {
		if clientId.Name == cel.clientId.Name {
			return fmt.Errorf("listener %s/%s already exists", clientId.Namespace, clientId.Name)
		}
	}

	w.listeners[clientId.Namespace] = append(w.listeners[clientId.Namespace], clientEventListener{
		clientId: clientId,
		listener: listener,
	})

	listener.Update(NsPolicySnapshot{
		policies: w.cache.List(clientId.Namespace, clientId.Labels),
	})

	return nil
}

func (w *PolicyWatcher) Unsubscribe(clientId ClientId) {
	w.lsMu.Lock()
	defer w.lsMu.Unlock()

	if _, exist := w.listeners[clientId.Namespace]; !exist {
		w.listeners[clientId.Namespace] = []clientEventListener{}
	}

	for idx, cel := range w.listeners[clientId.Namespace] {
		if clientId.Name == cel.clientId.Name {
			w.listeners[clientId.Namespace] = slices.Delete(w.listeners[clientId.Namespace], idx, idx+1)
			return
		}
	}
}

func objToPolicy(obj interface{}) (*models.Policy, error) {
	kubePolicy, ok := obj.(*v1beta1.Policy)
	if !ok {
		return nil, fmt.Errorf("can't parse added object: %s", obj)
	}

	rawPolicy, err := json.Marshal(kubePolicy.Spec.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal policy %s: %s", kubePolicy.Name, err.Error())
	}

	return &models.Policy{
		Name:      kubePolicy.Name,
		Namespace: kubePolicy.Namespace,
		Raw:       rawPolicy,
		Labels:    kubePolicy.Spec.Match.Labels,
	}, nil
}

func (w *PolicyWatcher) onAdd(obj interface{}) {
	policy, err := objToPolicy(obj)
	if err != nil {
		w.logger.Error(err.Error())
		return
	}

	w.logger.Info(fmt.Sprintf("policy %s/%s added", policy.Name, policy.Namespace))

	w.queue.Push(kubePolicyEvent{
		policy: *policy,
		op:     eventAddOp,
	})
}

func (w *PolicyWatcher) onUpdate(oldObj interface{}, newObj interface{}) {
	policy, err := objToPolicy(newObj)
	if err != nil {
		w.logger.Error(err.Error())
		return
	}

	w.logger.Info(fmt.Sprintf("policy %s/%s updated", policy.Name, policy.Namespace))

	w.queue.Push(kubePolicyEvent{
		policy: *policy,
		op:     eventUpdateOp,
	})
}

func (w *PolicyWatcher) onDelete(obj interface{}) {
	policy, err := objToPolicy(obj)
	if err != nil {
		w.logger.Error(err.Error())
		return
	}

	w.logger.Info(fmt.Sprintf("policy %s/%s deleted", policy.Name, policy.Namespace))

	w.queue.Push(kubePolicyEvent{
		policy: *policy,
		op:     eventDeleteOp,
	})
}

func (w *PolicyWatcher) pushPolicies(namespace string) {
	if _, exists := w.listeners[namespace]; !exists {
		return
	}
	for _, ls := range w.listeners[namespace] {
		ls.listener.Update(NsPolicySnapshot{
			policies: w.cache.List(namespace, ls.clientId.Labels),
		})
	}
}

func (w *PolicyWatcher) Start(ctx context.Context) error {
	w.queue.Consume(ctx, func(event kubePolicyEvent) error {
		w.lsMu.Lock()
		defer w.lsMu.Unlock()

		switch event.op {
		case eventAddOp:
			w.cache.Put(event.policy.Namespace, event.policy)
		case eventUpdateOp:
			w.cache.Put(event.policy.Namespace, event.policy)
		case eventDeleteOp:
			w.cache.Delete(event.policy.Namespace, event.policy.Name)
		default:
			w.logger.Error(fmt.Sprintf("undefined policy event operation: %d", event.op))
		}

		w.pushPolicies(event.policy.Namespace)

		return nil
	})

	return nil
}
