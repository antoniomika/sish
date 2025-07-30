Write-Host "Building Docker image for sish..." -ForegroundColor Cyan
docker build -t homiodev/sish:pr-2 .
if ($LASTEXITCODE -eq 0) {
    Write-Host "Docker image built successfully: homiodev/sish:pr-2" -ForegroundColor Green
    Write-Host ""
    Write-Host "To push the image, run: docker push homiodev/sish:pr-2" -ForegroundColor Yellow
} else {
    Write-Host "Error building Docker image" -ForegroundColor Red
}