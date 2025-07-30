# PowerShell script to build sish

# Set error action preference to stop on any error
$ErrorActionPreference = "Stop"

Write-Host "Building sish project..." -ForegroundColor Green

# Check if Go is installed
try {
    $goVersion = go version
    Write-Host "Using $goVersion" -ForegroundColor Cyan
} catch {
    Write-Host "Error: Go is not installed or not in PATH. Please install Go 1.24 or later." -ForegroundColor Red
    exit 1
}

# Download dependencies
Write-Host "Downloading dependencies..." -ForegroundColor Cyan
go mod download
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error downloading dependencies" -ForegroundColor Red
    exit 1
}

# Build for current platform
Write-Host "Building sish for current platform..." -ForegroundColor Cyan
go build -o sish.exe
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error building sish" -ForegroundColor Red
    exit 1
}

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "The executable 'sish.exe' has been created in the current directory." -ForegroundColor Green
Write-Host "Run it with: .\sish.exe" -ForegroundColor Yellow

# Ask if user wants to build for other platforms
$buildOthers = Read-Host "Do you want to build for other platforms? (y/n)"
if ($buildOthers -eq "y" -or $buildOthers -eq "Y") {
    # Build for Linux
    Write-Host "Building for Linux (amd64)..." -ForegroundColor Cyan
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    go build -o sish-linux-amd64
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error building for Linux" -ForegroundColor Red
    } else {
        Write-Host "Linux build completed: sish-linux-amd64" -ForegroundColor Green
    }
    
    # Build for macOS
    Write-Host "Building for macOS (amd64)..." -ForegroundColor Cyan
    $env:GOOS = "darwin"
    $env:GOARCH = "amd64"
    go build -o sish-darwin-amd64
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error building for macOS" -ForegroundColor Red
    } else {
        Write-Host "macOS build completed: sish-darwin-amd64" -ForegroundColor Green
    }
    
    # Reset environment variables
    $env:GOOS = ""
    $env:GOARCH = ""
}

Write-Host "All builds completed!" -ForegroundColor Green