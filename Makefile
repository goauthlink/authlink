VERSION ?= $(go run ./cmd/agent/main.go version) 
AGENT_IMAGE_NAME ?= ghcr.io/auth-policy-controller/agent

RELEASE_DIR = ./dist
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
AGENT_BIN := agent_$(GOOS)_$(GOARCH)

lint:
	golangci-lint run

test:
	go test ./... -v

clean:
	rm -rf ./dist/*

agent-build-bin:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(AGENT_BIN) agent/cmd/main.go 
	chmod +x $(AGENT_BIN)
	mv $(AGENT_BIN) $(RELEASE_DIR)/
	cd $(RELEASE_DIR)/ && shasum -a 256 $(AGENT_BIN) > $(AGENT_BIN).sha256

agent-build-image:
	docker build --build-arg="TARGETOS=${GOOS}" --build-arg="TARGETARCH=${GOARCH}" -f docker/Dockerfile.agent -t ${AGENT_IMAGE_NAME}:${VERSION} .

agent-publish-image:
	docker push ${AGENT_IMAGE_NAME}:${VERSION}

agent-test-image:
	docker run -it --rm ${AGENT_IMAGE_NAME}:${VERSION} version 