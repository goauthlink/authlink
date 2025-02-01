package fake

import (
	"context"
	"testing"

	"github.com/goauthlink/authlink/controller/apis/generated/clientset/versioned/fake"
	"github.com/goauthlink/authlink/controller/apis/policies/v1beta1"
	"github.com/goauthlink/authlink/controller/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DeletePolicy(t *testing.T, clientSet *fake.Clientset, ns, name string) {
	t.Helper()
	if err := clientSet.AuthlinkV1beta1().Policies(ns).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		t.Error(err)
	}
}

func CreatePolicy(t *testing.T, clientSet *fake.Clientset, policy models.Policy) models.Policy {
	t.Helper()
	_, err := clientSet.AuthlinkV1beta1().Policies(policy.Namespace).Create(context.Background(), &v1beta1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.Name,
		},
		Spec: v1beta1.PolicySpec{
			Config: policy.Config,
			Match: v1beta1.PolicyMatch{
				Labels: policy.Labels,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Error(err)
	}

	return policy
}
