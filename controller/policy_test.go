package controller

import (
	"testing"

	"github.com/goauthlink/authlink/controller/models"
	"github.com/stretchr/testify/require"
)

func Test_MatchLabels(t *testing.T) {
	ps := NewInMemPolicyStorage()
	ps.Put("default", models.Policy{
		Name:   "policy-1",
		Raw:    []byte{},
		Labels: map[string]string{"app": "service", "team": "core"},
	})

	ps.Put("default", models.Policy{
		Name:   "policy-2",
		Raw:    []byte{},
		Labels: map[string]string{"app": "service"},
	})

	ps.Put("default", models.Policy{
		Name:   "policy-3",
		Raw:    []byte{},
		Labels: map[string]string{"app": "service", "team": "infra"},
	})

	matchedPolicies := ps.List("default", models.LabelSet{"app": "service", "team": "core"})
	require.Len(t, matchedPolicies, 1)
	require.Equal(t, matchedPolicies[0].Name, "policy-1")
}
