#!/usr/bin/env bash

# Copyright 2025 The AuthLink Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

echo $SCRIPT_ROOT

GOPATH=$(go env GOPATH)

CODEGEN_PKG=${CODEGEN_PKG:-$GOPATH/pkg/mod/k8s.io/code-generator@v0.32.0}

source "${CODEGEN_PKG}/kube_codegen.sh"

THIS_PKG="github.com/goauthlink/authlink"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/sdk/policy"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/controller/apis"

kube::codegen::gen_client \
    --with-watch \
    --output-dir "${SCRIPT_ROOT}/controller/apis/generated" \
    --output-pkg "${THIS_PKG}/controller/apis/generated" \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/controller/apis"