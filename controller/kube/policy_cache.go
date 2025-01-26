// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import (
	"sync"

	"github.com/goauthlink/authlink/controller/models"
)

type policyCache struct {
	items map[string]map[string]models.Policy
	mu    sync.Mutex
}

func newPolicyCache() *policyCache {
	return &policyCache{
		items: map[string]map[string]models.Policy{},
		mu:    sync.Mutex{},
	}
}

func (ps *policyCache) Put(ns string, policy models.Policy) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.items[ns]; !exists {
		ps.items[ns] = map[string]models.Policy{}
	}

	ps.items[ns][policy.Name] = policy
}

func (ps *policyCache) List(ns string, matchingLabels models.LabelSet) []models.Policy {
	policies := []models.Policy{}
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.items[ns]; !exists {
		return policies
	}

	for _, policy := range ps.items[ns] {
		if isLabelsMatched(matchingLabels, policy.Labels) {
			policies = append(policies, policy)
		}
	}

	return policies
}

func (ps *policyCache) Delete(ns, name string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.items[ns]; !exists {
		return
	}

	delete(ps.items[ns], name)
}
