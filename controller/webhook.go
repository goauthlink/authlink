// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"

	"github.com/goauthlink/authlink/controller/apis/policies/v1beta1"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/goauthlink/authlink/sdk/policy"
)

func newValidatingWebhookHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reviewRequest := parseAdmissionReviewRequest(w, r)

		expectedResource := metav1.GroupVersionResource{
			Group:    v1beta1.SchemeGroupVersion.Group,
			Version:  v1beta1.SchemeGroupVersion.Version,
			Resource: "policies",
		}

		if reviewRequest.Resource != expectedResource {
			http.Error(w, fmt.Sprintf("admission review can't be used: unexpected object %s:%s/%s",
				reviewRequest.Kind.Group,
				reviewRequest.Kind.Kind,
				reviewRequest.Kind.Version), http.StatusBadRequest)
		}

		pol := v1beta1.Policy{}
		if err := json.Unmarshal([]byte(reviewRequest.Object.Raw), &pol); err != nil {
			body := admissionReviewResponse("invalid policy object", http.StatusBadRequest, false, reviewRequest.UID)
			writeResponse(w, http.StatusBadRequest, body)
			return
		}

		_, err := policy.PrepareConfig(pol.Spec.Config)
		if err != nil {
			body := admissionReviewResponse(fmt.Sprintf("policy validation: %s", err.Error()), http.StatusBadRequest, false, reviewRequest.UID)
			writeResponse(w, http.StatusBadRequest, body)
			return
		}

		body := admissionReviewResponse("", http.StatusOK, true, reviewRequest.UID)
		writeResponse(w, http.StatusOK, body)
	})
}

func newInjectionWebhookHandler(config InectionConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reviewRequest := parseAdmissionReviewRequest(w, r)
		if reviewRequest == nil {
			return
		}
		if reviewRequest.Resource.String() != "v1/Pod" {
			writeResponse(w, http.StatusBadRequest,
				admissionReviewResponse("unexpected k8s object type",
					http.StatusBadRequest,
					false,
					reviewRequest.UID))
		}

		patch, err := createJsonPatch(config)
		if err != nil {
			http.Error(w, fmt.Sprintf("could not create pod patch: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		patchType := admissionv1.PatchTypeJSONPatch
		reviewResponse := admissionv1.AdmissionReview{
			Response: &admissionv1.AdmissionResponse{
				UID:       reviewRequest.UID,
				Allowed:   true,
				Patch:     patch,
				PatchType: &patchType,
			},
		}

		responseBody, err := json.Marshal(reviewResponse)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid review response: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		writeResponse(w, http.StatusOK, responseBody)
	})
}

func writeResponse(w http.ResponseWriter, code int, body []byte) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(body)
}

func parseAdmissionReviewRequest(w http.ResponseWriter, r *http.Request) *admissionv1.AdmissionRequest {
	bodybuf := new(bytes.Buffer)
	bodybuf.ReadFrom(r.Body)

	if bodybuf.Len() == 0 {
		http.Error(w, "admission request body is empty", http.StatusBadRequest)
		return nil
	}

	println(bodybuf.String())

	var reviewRequest admissionv1.AdmissionReview

	if err := json.Unmarshal(bodybuf.Bytes(), &reviewRequest); err != nil {
		http.Error(w, fmt.Sprintf("could not parse admission review request: %s", err.Error()), http.StatusBadRequest)
		return nil
	}
	if reviewRequest.Request == nil {
		http.Error(w, "admission review can't be used: Request field is nil", http.StatusBadRequest)
		return nil
	}

	return reviewRequest.Request
}

func admissionReviewResponse(message string, code int, allowed bool, uid types.UID) []byte {
	revresp := admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: message,
				Code:    int32(code),
			},
			UID:     uid,
			Allowed: allowed,
		},
	}

	responseBody, _ := json.Marshal(revresp)

	return responseBody
}

var injectContainerTemplate = `[
{
	"op": "add",
	"path": "/spec/containers/-",
	"value": {
		"image": "{{ .Image }}",
		"imagePullPolicy": "{{ .PullPolicy }}",
		"name": "{{ .Name }}",
		"args": [],
		"ports": [
			{"containerPort": {{ .HttpPort }}},
			{"containerPort": {{ .GrpcPort }}}
		],
		"readinessProbe": {
			"httpGet": {
			"path": "/health",
			"port": {{ .HttpPort }}
			}
		},
		"livenessProbe": {
			"httpGet": {
			"path": "/health",
			"port": {{ .HttpPort }}
			}
		}
		{{ if not (eq .Resources nil) }},
		"resources": {
			{{- if not (eq .Resources.Requests nil) }}
			"requests": {
			{{- if not (eq .Resources.Requests.Cpu) }}
			"cpu": "{{ .Resources.Requests.Cpu }}",
			{{- end }}
			{{- if not (eq .Resources.Requests.Memory nil) }}
			"memory": "{{ .Resources.Requests.Memory }}",
			{{- end }}
			}
			{{- end }}
			{{- if not (eq .Resources.Limits nil) }}
			"limits": {
			{{- if not (eq .Resources.Limits.Cpu nil) }}
			"cpu": "{{ .Resources.Limits.Cpu }}",
			{{- end }}
			{{- if not (eq .Resources.Limits.Memory nil) }}
			"memory": "{{ .Resources.Limits.Memory }}"
			{{- end }}
			}
			{{- end }}
		}
		{{- end }}
	}
}]
`

// todo: apply pod annotation for configuring pod

func createJsonPatch(injectionConfig InectionConfig) ([]byte, error) {
	temp, err := template.New("inject").Parse(injectContainerTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse injection template: %w", err)
	}

	var patchBuf bytes.Buffer
	if err := temp.Execute(&patchBuf, injectionConfig); err != nil {
		return nil, fmt.Errorf("template injection template: %w", err)
	}

	return patchBuf.Bytes(), nil
}
