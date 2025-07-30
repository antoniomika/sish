# How to Build the Docker Image for sish

## Windows Users

If you're using Windows, you have two simple options to build the Docker image:

### Option 1: Using the Batch File

```cmd
docker-build.bat
```

### Option 2: Using the PowerShell Script

```powershell
.\docker-build.ps1
```

Both scripts:
- Build the Docker image directly
- Tag it as `homiodev/sish:pr-2`
- Provide feedback on the build process

## Linux/macOS Users: Using `make docker`

On Linux or macOS, the recommended and simplest way to build the Docker image is using the `make docker` command:

```bash
make docker
```

This command:
- Builds the Docker image directly
- Tags it as `homiodev/sish:pr-2`
- Does not build the Go binary separately first
- Is the most straightforward approach

## Alternative Approach: Using `build.sh`

You can also use the `build.sh` script:

```bash
# Make the script executable first (if needed)
chmod +x build.sh

# Run the script
./build.sh
```

This script:
- First builds the Go binary for Linux
- Then builds the Docker image
- Tags it as `homiodev/sish:pr-2`
- Provides more verbose output during the build process

## Differences Between the Approaches

| Feature | `make docker` | `build.sh` |
|---------|--------------|------------|
| Builds Go binary first | No | Yes |
| Build time | Faster | Slightly slower |
| Output verbosity | Minimal | More detailed |
| Final result | Same Docker image | Same Docker image |

## Pushing the Docker Image

After building the image, you can push it to a Docker registry:

```bash
make push
```

Or directly with Docker:

```bash
docker push homiodev/sish:pr-2
```

## Running the Docker Container

Once built, you can run the container:

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