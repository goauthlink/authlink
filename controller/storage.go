// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"sync"

	"github.com/goauthlink/authlink/controller/models"
)

//go:generate mockery --case underscore --name PolicyStorage --with-expecter

type PolicyStorage interface {
	Put(ns string, policy models.Policy)
	List(ns string, needLabels models.LabelSet) []models.Policy
	Delete(ns, name string)
}

type ImMemPolicyStorage struct {
	items map[string]map[string]models.Policy
	mu    sync.Mutex
}

func NewInMemPolicyStorage() *ImMemPolicyStorage {
	return &ImMemPolicyStorage{
		items: map[string]map[string]models.Policy{},
		mu:    sync.Mutex{},
	}
}

func (ps *ImMemPolicyStorage) Put(ns string, policy models.Policy) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.items[ns]; !exists {
		ps.items[ns] = map[string]models.Policy{}
	}

	ps.items[ns][policy.Name] = policy
}

func (ps *ImMemPolicyStorage) List(ns string, needLabels models.LabelSet) []models.Policy {
	policies := []models.Policy{}
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.items[ns]; !exists {
		return policies
	}

	for _, item := range ps.items[ns] {
		matched := true
		for lname, lvalue := range needLabels {
			if itemValue, exists := item.Labels[lname]; !exists || itemValue != lvalue {
				matched = false
				break
			}
		}

		if matched {
			policies = append(policies, item)
		}
	}

	return policies
}

func (ps *ImMemPolicyStorage) Delete(ns, name string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.items[ns]; !exists {
		return
	}

	delete(ps.items[ns], name)
}
