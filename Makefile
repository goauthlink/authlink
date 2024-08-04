export VERSION ?= 0.0.0

lint:
	golangci-lint run

test:
	go test ./... -v

docker_test:
	docker build -f Dockerfile . -t apc-test-image && \
	docker run -it -v ./examples/test_policy.yaml:/apc/test_policy.yaml apc-test-image version 