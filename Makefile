.PHONY: all docker clean build linux-build push

# Default target is now docker
all: docker

# Build Docker image
docker:
	docker build -t homiodev/sish:pr-2 .

# Push Docker image
push:
	docker push homiodev/sish:pr-2

# Clean build artifacts
clean:
	rm -f sish sish-*

# Basic build for current platform
build:
	go build -o sish

# Build specifically for Linux
linux-build:
	GOOS=linux GOARCH=amd64 go build -o sish-linux-amd64

# Optimized release build
release:
	go build -ldflags="-s -w" -o sish