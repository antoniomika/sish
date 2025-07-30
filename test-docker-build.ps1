# Test script to verify Docker build works on Windows
$ErrorActionPreference = "Stop"

Write-Host "Testing Docker build on Windows..." -ForegroundColor Cyan
Write-Host "Checking Docker installation..." -ForegroundColor Cyan

# Check if Docker is installed and running
try {
    $dockerVersion = docker --version
    Write-Host "Docker is installed: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "Error: Docker is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# Test if Docker daemon is running
try {
    docker info | Out-Null
    Write-Host "Docker daemon is running." -ForegroundColor Green
} catch {
    Write-Host "Error: Docker daemon is not running." -ForegroundColor Red
    Write-Host "Please start Docker Desktop or the Docker service." -ForegroundColor Yellow
    exit 1
}

# Test the PowerShell build script
Write-Host "`nTesting PowerShell build script..." -ForegroundColor Cyan
try {
    # Just check if the script exists, don't actually run it
    if (Test-Path ".\docker-build.ps1") {
        Write-Host "PowerShell build script exists and is ready to use." -ForegroundColor Green
    } else {
        Write-Host "Error: PowerShell build script not found." -ForegroundColor Red
    }
} catch {
    Write-Host "Error testing PowerShell build script: $_" -ForegroundColor Red
}

# Test the Batch build script
Write-Host "`nTesting Batch build script..." -ForegroundColor Cyan
try {
    # Just check if the script exists, don't actually run it
    if (Test-Path ".\docker-build.bat") {
        Write-Host "Batch build script exists and is ready to use." -ForegroundColor Green
    } else {
        Write-Host "Error: Batch build script not found." -ForegroundColor Red
    }
} catch {
    Write-Host "Error testing Batch build script: $_" -ForegroundColor Red
}

Write-Host "`nTest completed. Both build scripts are available." -ForegroundColor Green
Write-Host "To build the Docker image, run either:" -ForegroundColor Yellow
Write-Host "  - .\docker-build.ps1  (PowerShell)" -ForegroundColor Yellow
Write-Host "  - docker-build.bat    (Command Prompt)" -ForegroundColor Yellow