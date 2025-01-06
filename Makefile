# Copyright 2025 The AuthLink Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

VERSION ?= $(shell go run ./agent/cmd/main.go version) 
REGISTRY_REPOSITORY ?= ghcr.io/goauthlink
RELEASE_DIR = ./dist
TARGET_OS ?= $(shell go env GOOS)
TARGET_ARCH ?= $(shell go env GOARCH)
OUTPUT_TYPE ?= docker
PLATFORM ?= $(TARGET_OS)/$(TARGET_ARCH)
BIN_PLATFORM ?= $(TARGET_OS)_$(TARGET_ARCH)

lint:
	golangci-lint run

tests:
	go test ./... -v

docker-buildx-builder:
	if ! docker buildx ls | grep -q container-builder; then\
		docker buildx create --name container-builder --use --bootstrap;\
	fi

define agent-build-bin
	mkdir -p $(RELEASE_DIR)
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build -o $(2)-$(BIN_PLATFORM) $(1) 
	chmod +x $(2)-$(BIN_PLATFORM)
	mv $(2)-$(BIN_PLATFORM) $(RELEASE_DIR)/
	cd $(RELEASE_DIR)/ \
		&& tar -zcvf $(2)-$(BIN_PLATFORM).tar.gz $(2)-$(BIN_PLATFORM) \
		&& shasum -a 256 $(2)-$(BIN_PLATFORM).tar.gz > $(2)-$(BIN_PLATFORM).tar.gz.sha256
endef

define agent-build-image
	docker buildx build \
		--output=type=${OUTPUT_TYPE} \
		--build-arg BIN=$(2) \
		--platform="$(PLATFORM)" \
		--tag ${REGISTRY_REPOSITORY}/$(2):${VERSION} \
		--tag ${REGISTRY_REPOSITORY}/$(2):latest \
		-f agent/docker/Dockerfile .
endef

agent-build-bin:
	$(call agent-build-bin,agent/cmd/main.go,agent)

envoy-agent-build-bin:
	$(call agent-build-bin,envoy/cmd/main.go,envoy-agent)

agent-build-image: docker-buildx-builder
	$(call agent-build-image,envoy/cmd/main.go,agent)

envoy-agent-build-image: docker-buildx-builder
	$(call agent-build-image,envoy/cmd/main.go,envoy-agent)