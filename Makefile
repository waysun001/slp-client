.PHONY: build build-linux build-arm64 clean

VERSION := 1.0.0
BUILD_TIME := $(shell date +%Y%m%d%H%M%S)
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

build:
	go build -ldflags "$(LDFLAGS)" -o slp-client ./cmd/slp-client/

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o slp-client-linux-amd64 ./cmd/slp-client/

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o slp-client-linux-arm64 ./cmd/slp-client/

build-all: build-linux build-arm64

clean:
	rm -f slp-client slp-client-*

test:
	go test -v ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy
