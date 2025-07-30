#!/bin/bash
# Shell script to build sish for Linux only

# Exit on error
set -e

echo -e "\033[0;32mBuilding sish project...\033[0m"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "\033[0;31mError: Go is not installed or not in PATH. Please install Go 1.24 or later.\033[0m"
    exit 1
fi

# Show Go version
GO_VERSION=$(go version)
echo -e "\033[0;36mUsing $GO_VERSION\033[0m"

# Download dependencies
echo -e "\033[0;36mDownloading dependencies...\033[0m"
go mod download

# Build for Linux
echo -e "\033[0;36mBuilding sish for Linux...\033[0m"
go build -o sish

echo -e "\033[0;32mBuild completed successfully!\033[0m"
echo -e "\033[0;32mThe executable 'sish' has been created in the current directory.\033[0m"
echo -e "\033[0;33mRun it with: ./sish\033[0m"

# Build Docker image
echo -e "\033[0;36mBuilding Docker image...\033[0m"
docker build -t homiodev/sish:pr-2 .
if [ $? -eq 0 ]; then
    echo -e "\033[0;32mDocker image built successfully: homiodev/sish:pr-2\033[0m"
else
    echo -e "\033[0;31mError building Docker image\033[0m"
fi

echo -e "\033[0;32mAll builds completed!\033[0m"
echo -e "\033[0;33mTo push the Docker image, run: docker push homiodev/sish:pr-2\033[0m"