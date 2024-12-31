# Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

VERSION ?= $(shell go run ./cmd/agent/main.go version) 
AGENT_IMAGE_NAME ?= ghcr.io/auth-request-agent/agent

RELEASE_DIR = ./dist
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
OUTPUT_TYPE ?= docker
PLATFORM ?= $(GOARCH)/$(GOOS)
AGENT_BIN := agent_$(GOOS)_$(GOARCH)

lint:
	golangci-lint run

tests:
	go test ./... -v

clean-bin:
	rm -rf ${RELEASE_DIR}/*

version:
	echo $(VERSION)

docker-buildx-builder:
	if ! docker buildx ls | grep -q container-builder; then\
		docker buildx create --name container-builder --use --bootstrap;\
	fi

agent-build-bin:
	mkdir -p $(RELEASE_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(AGENT_BIN) cmd/agent/main.go 
	chmod +x $(AGENT_BIN)
	mv $(AGENT_BIN) $(RELEASE_DIR)/
	cd $(RELEASE_DIR)/ && tar -zcvf $(AGENT_BIN).tar.gz $(AGENT_BIN) && shasum -a 256 $(AGENT_BIN).tar.gz > $(AGENT_BIN).tar.gz.sha256

agent-build-image: docker-buildx-builder
	docker buildx build $(PLATFORM) \
		--output=type=${OUTPUT_TYPE} \
		--platform="$(PLATFORM)"
		-f Dockerfile.agent \
		-t ${AGENT_IMAGE_NAME}:${VERSION} .