# Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

VERSION ?= $(go run ./cmd/agent/main.go version) 
AGENT_IMAGE_NAME ?= ghcr.io/auth-request-agent/agent

RELEASE_DIR = ./dist
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
AGENT_BIN := agent_$(GOOS)_$(GOARCH)

lint:
	golangci-lint run

tests:
	go test ./... -v

clean-bin:
	rm -rf ${RELEASE_DIR}/*

agent-build-bin:
	mkdir -p $(RELEASE_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(AGENT_BIN) cmd/agent/main.go 
	chmod +x $(AGENT_BIN)
	mv $(AGENT_BIN) $(RELEASE_DIR)/
	cd $(RELEASE_DIR)/  && tar -zcvf $(AGENT_BIN).tar.gz $(AGENT_BIN) && shasum -a 256 $(AGENT_BIN).tar.gz > $(AGENT_BIN).tar.gz.sha256

agent-build-image:
	docker build --build-arg="TARGETOS=${GOOS}" --build-arg="TARGETARCH=${GOARCH}" -f Dockerfile.agent -t ${AGENT_IMAGE_NAME}:${VERSION} .

agent-publish-image:
	docker push ${AGENT_IMAGE_NAME}:${VERSION}
	docker tag ${AGENT_IMAGE_NAME}:${VERSION} ${AGENT_IMAGE_NAME}:latest
	docker push ${AGENT_IMAGE_NAME}:latest

agent-test-image:
	docker run -it --rm ${AGENT_IMAGE_NAME}:${VERSION} version 