BINARY_NAME := auth-service
BUILD_DIR := build
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -X github.com/vibast-solutions/ms-go-auth/cmd.Version=$(VERSION) \
           -X github.com/vibast-solutions/ms-go-auth/cmd.Commit=$(COMMIT)

.PHONY: build build-linux-arm64 build-linux-amd64 build-all clean

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .

build-linux-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

build-linux-amd64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .

build-all: build build-linux-arm64 build-linux-amd64

clean:
	rm -rf $(BUILD_DIR)
