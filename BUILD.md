# Building the sish Project

This document provides instructions on how to build the sish project from source, with a focus on Docker and Linux builds.

## Prerequisites

- Docker (recommended)
- Go 1.24 or later (for native builds)
- Git (to clone the repository)

## Option 1: Building with Docker (Recommended)

The easiest and recommended way to build and use sish is with Docker:

### 1. Clone the Repository

```bash
git clone https://github.com/antoniomika/sish.git
cd sish
```

### 2. Build the Docker Image

```bash
# Using make
make docker

# Or using docker directly
docker build -t homiodev/sish:pr-2 .
```

### 3. Push the Docker Image (Optional)

```bash
# Using make
make push

# Or using docker directly
docker push homiodev/sish:pr-2
```

### 4. Run the Docker Container

```bash
docker run -itd --name sish \
  -v ~/sish/ssl:/ssl \
  -v ~/sish/keys:/keys \
  -v ~/sish/pubkeys:/pubkeys \
  --net=host homiodev/sish:pr-2 \
  --ssh-address=:22 \
  --http-address=:80 \
  --https-address=:443 \
  --https=true \
  --https-certificate-directory=/ssl \
  --authentication-keys-directory=/pubkeys \
  --private-keys-directory=/keys \
  --bind-random-ports=false
```

## Option 2: Building Natively on Linux

If you prefer to build natively on Linux:

### 1. Clone the Repository

```bash
git clone https://github.com/antoniomika/sish.git
cd sish
```

### 2. Download Dependencies

```bash
go mod download
```

### 3. Build Using the Script

```bash
# Make the script executable
chmod +x build.sh

# Run the build script
./build.sh
```

### 4. Build Using Make

The project includes a Makefile with several useful targets:

```bash
# Build for your current platform
make build

# Build specifically for Linux
make linux-build

# Create an optimized release build
make release

# Clean up build artifacts
make clean
```

### 5. Build Using Go Directly

To build the project manually:

```bash
# Build for current platform
go build -o sish

# Build specifically for Linux
GOOS=linux GOARCH=amd64 go build -o sish-linux-amd64
```

## Running the Application

After building natively, you can run the application:

```bash
# Run with default settings
./sish

# Run with custom configuration
./sish --ssh-address=:22 --http-address=:80 --https-address=:443
```

For a complete list of configuration options, refer to the README.md file or run:

```bash
./sish --help
```

## Creating an Optimized Release Build

To create an optimized release build with a smaller binary size:

```bash
go build -ldflags="-s -w" -o sish
```

The `-ldflags="-s -w"` option reduces the binary size by removing debug information and the symbol table.