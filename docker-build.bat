@echo off
echo Building Docker image for sish...
docker build -t homiodev/sish:pr-2 .
if %ERRORLEVEL% EQU 0 (
    echo Docker image built successfully: homiodev/sish:pr-2
    echo.
    echo To push the image, run: docker push homiodev/sish:pr-2
) else (
    echo Error building Docker image
)