VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/gofika/polyctl/internal/cli.Version=$(VERSION)

.PHONY: build install test vet fmt lint clean

build:
	go build -ldflags '$(LDFLAGS)' -o bin/polyctl ./cmd/polyctl

install:
	go install -ldflags '$(LDFLAGS)' ./cmd/polyctl

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: fmt vet

clean:
	rm -rf bin dist
