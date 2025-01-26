// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import (
	"testing"

	"github.com/goauthlink/authlink/controller/models"
)

func Test_ListWithLabels(t *testing.T) {
	const ns = "default"

	ps := newPolicyCache()
	ps.Put(ns, models.Policy{
		Name:   "policy-1",
		Raw:    []byte{},
		Labels: map[string]string{"l1": "v1"},
	})

	ps.Put(ns, models.Policy{
		Name:   "policy-2",
		Raw:    []byte{},
		Labels: map[string]string{"l1": "v1", "l2": "v2"},
	})

	ps.Put(ns, models.Policy{
		Name:   "policy-3",
		Raw:    []byte{},
		Labels: map[string]string{"l3": "v3"},
	})

	matchedPolicies := ps.List(ns, models.LabelSet{"l1": "v1", "cl1": "cv2"})
	if len(matchedPolicies) < 1 || matchedPolicies[0].Name != "policy-1" {
		t.Errorf("expected policy-1 must be matched, matched %s", matchedPolicies)
	}

	matchedPolicies = ps.List(ns, models.LabelSet{"l1": "v1", "l2": "v2", "cl1": "cv2"})
	if len(matchedPolicies) < 2 || matchedPolicies[0].Name != "policy-1" || matchedPolicies[1].Name != "policy-2" {
		t.Errorf("expected policy-1 and policy-2 must be matched, matched %s", matchedPolicies)
	}

	matchedPolicies = ps.List(ns, models.LabelSet{"l1": "v1", "l3": "v3", "cl1": "cv2"})
	if len(matchedPolicies) < 2 || matchedPolicies[0].Name != "policy-1" || matchedPolicies[1].Name != "policy-3" {
		t.Errorf("expected policy-1 and policy-3 must be matched, matched %s", matchedPolicies)
	}
}
