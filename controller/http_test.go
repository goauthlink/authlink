// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/goauthlink/authlink/controller/apis/policies/v1beta1"
	"github.com/goauthlink/authlink/sdk/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
)

var (
	yamlSerializer *kjson.Serializer
	jsonSerializer *kjson.Serializer
)

func init() {
	yamlSerializer = kjson.NewYAMLSerializer(kjson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
	jsonSerializer = kjson.NewSerializer(kjson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme, true)
}

func initHttpServer(t *testing.T, cfg *Config, opts ...ServerOpt) (*httpServer, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	fCfg := DefaultConfig()
	if cfg != nil {
		fCfg = *cfg
	}

	srvOptions := []ServerOpt{
		WithLogger(logger),
	}
	srvOptions = append(srvOptions, opts...)

	httpServer, err := NewHttpServer(fCfg, srvOptions...)
	require.NoError(t, err)

	return httpServer, buf
}

func createAdmissionPolicyRequest(t *testing.T, policy *v1beta1.Policy) []byte {
	rawPolicy, err := json.Marshal(policy)
	require.NoError(t, err)

	admReview := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: "uid",
			Resource: metav1.GroupVersionResource{
				Group:    v1beta1.SchemeGroupVersion.Group,
				Version:  v1beta1.SchemeGroupVersion.Version,
				Resource: "policies",
			},
			Name:      "test-policy",
			Namespace: "test-namespace",
			Operation: "CREATE",
			Object: runtime.RawExtension{
				Raw: rawPolicy,
			},
		},
	}

	body, err := json.Marshal(admReview)
	require.NoError(t, err)

	return body
}

func createInjectionRequest(t *testing.T, pod corev1.Pod) []byte {
	rawPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}

	review := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "test-uid",
			Kind: metav1.GroupVersionKind{},
			Resource: metav1.GroupVersionResource{
				Group:    corev1.SchemeGroupVersion.Group,
				Version:  corev1.SchemeGroupVersion.Version,
				Resource: "Pod",
			},
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Operation: "CREATE",
			Object: runtime.RawExtension{
				Raw: rawPod,
			},
		},
	}

	body, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}

	return body
}

func applyJSONPatch(t *testing.T, input, patch []byte) []byte {
	t.Helper()
	p, err := jsonpatch.DecodePatch(patch)
	if err != nil {
		t.Fatal(err, string(patch))
	}

	patchedJSON, err := p.Apply(input)
	if err != nil {
		t.Fatal(err)
	}

	return prettyJSON(patchedJSON, t)
}

func prettyJSON(inputJSON []byte, t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Indent(&buf, inputJSON, "", "  "); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func podToYaml(t *testing.T, pod *corev1.Pod) *bytes.Buffer {
	buf := bytes.Buffer{}
	if err := yamlSerializer.Encode(pod, &buf); err != nil {
		t.Fatal(err)
	}

	return &buf
}

func yamlFileToPod(t *testing.T, path string) *corev1.Pod {
	raw := readFileOrCreate(t, path)

	pod := corev1.Pod{}
	gvk := pod.GroupVersionKind()
	_, _, err := yamlSerializer.Decode(raw, &gvk, &pod)
	if err != nil {
		t.Fatal(err)
	}

	return &pod
}

func readFileOrCreate(t *testing.T, path string) []byte {
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		_, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
	}

	if raw, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else {
		return raw
	}

	return nil
}

func Test_InjectWebhook(t *testing.T) {
	config := DefaultConfig()
	tc := []struct {
		config       func() InectionConfig
		wantSnapshot string
		wantCode     int32
	}{
		{
			wantSnapshot: "service",
			config: func() InectionConfig {
				return config.InjectionConfig
			},
		},
	}

	for _, tcc := range tc {
		t.Run(tcc.wantSnapshot, func(t *testing.T) {
			w := httptest.NewRecorder()
			httpServer, _ := initHttpServer(t, &Config{
				InjectionConfig: tcc.config(),
			})

			inputPod := yamlFileToPod(t, "./testdata/inject/"+tcc.wantSnapshot+".input.yaml")
			admRequestBody := createInjectionRequest(t, *inputPod)
			request := httptest.NewRequest(http.MethodPost, "http://localhost:8181/admissionv1/inject", bytes.NewBuffer(admRequestBody))
			httpServer.httpserver.Handler.ServeHTTP(w, request)
			rqResult := w.Result()

			assert.Equal(t, http.StatusOK, rqResult.StatusCode)

			responseBody, err := io.ReadAll(rqResult.Body)
			if err != nil {
				t.Fatalf("could not read body: %v", err)
			}

			admReview := admissionv1.AdmissionReview{}
			if err := json.Unmarshal(responseBody, &admReview); err != nil {
				t.Fatal(err, string(responseBody))
			}

			if len(tcc.wantSnapshot) > 0 {
				inputPodJson, err := json.Marshal(inputPod)
				if err != nil {
					t.Fatal(err)
				}
				injectedPodJson := applyJSONPatch(t, inputPodJson, admReview.Response.Patch)
				injectedPod := corev1.Pod{}
				if err := json.Unmarshal(injectedPodJson, &injectedPod); err != nil {
					t.Fatal(err)
				}

				snapshotPath := "./testdata/inject/" + tcc.wantSnapshot + ".injected.yaml"
				injectedYamlBuf := podToYaml(t, &injectedPod)
				snapshotPod := yamlFileToPod(t, snapshotPath)
				snapshotYamlBuf := podToYaml(t, snapshotPod)

				assert.Equal(t, snapshotYamlBuf.String(), injectedYamlBuf.String())

				if err := os.WriteFile(snapshotPath, injectedYamlBuf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
		})
	}
}

func Test_InjectUnexpectedObjectType(t *testing.T) {
	w := httptest.NewRecorder()
	httpServer, _ := initHttpServer(t, &Config{
		InjectionConfig: DefaultConfig().InjectionConfig,
	})

	deploymentYaml, err := os.ReadFile("./testdata/inject/deployment.input.yaml")
	if err != nil {
		t.Fatal(err)
	}

	deployment := appsv1.Deployment{}
	gvk := deployment.GroupVersionKind()
	_, _, err = yamlSerializer.Decode(deploymentYaml, &gvk, &deployment)
	if err != nil {
		t.Fatal(err)
	}

	rawBuf := bytes.NewBuffer([]byte{})
	if err := jsonSerializer.Encode(&deployment, rawBuf); err != nil {
		t.Fatal(err)
	}

	review := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "test-uid",
			Kind: metav1.GroupVersionKind{},
			Resource: metav1.GroupVersionResource{
				Group:    appsv1.SchemeGroupVersion.Group,
				Version:  appsv1.SchemeGroupVersion.Version,
				Resource: "Deployment",
			},
			Name:      deployment.Name,
			Namespace: deployment.Namespace,
			Operation: "CREATE",
			Object: runtime.RawExtension{
				Raw: rawBuf.Bytes(),
			},
		},
	}

	admRequestBody, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "http://localhost:8181/admissionv1/inject", bytes.NewBuffer(admRequestBody))
	httpServer.httpserver.Handler.ServeHTTP(w, request)
	rqResult := w.Result()

	assert.Equal(t, http.StatusBadRequest, rqResult.StatusCode)
}

func Test_ValidationWebHook(t *testing.T) {
	w := httptest.NewRecorder()
	httpServer, _ := initHttpServer(t, nil)

	body := createAdmissionPolicyRequest(t, &v1beta1.Policy{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Spec: v1beta1.PolicySpec{
			Config: policy.Config{
				Cn:       []policy.Cn{},
				Vars:     map[string][]string{},
				Default:  []string{},
				Policies: []policy.Policy{},
			},
			Match: v1beta1.PolicyMatch{},
		},
	})

	request := httptest.NewRequest(http.MethodPost, "http://localhost:8181/admissionv1/validate", bytes.NewBuffer(body))

	httpServer.httpserver.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
}

func Test_ValidationBadPolicy(t *testing.T) {
	w := httptest.NewRecorder()
	httpServer, _ := initHttpServer(t, nil)

	body := createAdmissionPolicyRequest(t, &v1beta1.Policy{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Spec: v1beta1.PolicySpec{
			Config: policy.Config{
				Cn:      []policy.Cn{},
				Vars:    map[string][]string{},
				Default: []string{},
				Policies: []policy.Policy{{
					Uri:     []string{""},
					Methods: []string{"w"},
					Allow:   []string{},
				}},
			},
			Match: v1beta1.PolicyMatch{},
		},
	})

	request := httptest.NewRequest(http.MethodPost, "http://localhost:8181/admissionv1/validate", bytes.NewBuffer(body))

	httpServer.httpserver.Handler.ServeHTTP(w, request)

	t.Log(w.Body.String())
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
