sish
====

An open source serveo/ngrok alternative.

## Deploy
Builds are made using Google Cloud Build. Feel free to either use the automated binaries or to build your own.

1. Pull the Docker image
    - `docker pull gcr.io/sishio/sish:latest`
2. Run the image
    - ```bash
      docker run -itd -p 2222:2222 --name sish \
          --restart always gcr.io/sishio/sish:latest \
          -sish.addr=":2222" -sish.http=":8080" -sish.domain="ssi.sh"
      ```
3. SSH to your host to communicate with sish
    - `ssh -p 2222 -R 80:localhost:8080 ssi.sh`

## How it works
SSH can normally forward local and remote ports. This service implements an SSH server that only does that and nothing else. The service supports multiplexing connections over HTTP/HTTPS with WebSocket support. Just assign a remote port as port `80` to proxy HTTP traffic and `443` to proxy HTTPS traffic. If you use any other remote port, the server will listen to the port for connections, but only if that port is available.

## CLI Flags
```
sh-3.2# ./sish -h
Usage of ./sish:
  -sish.addr string
        The address to listen for SSH connections (default "localhost:2222")
  -sish.auth
        Whether or not to require auth on the SSH service
  -sish.debug
        Whether or not to print debug information
  -sish.domain string
        The domain for HTTP(S) multiplexing (default "ssi.sh")
  -sish.http string
        The address to listen for HTTP connections (default "localhost:80")
  -sish.https string
        The address to listen for HTTPS connections (default "localhost:443")
  -sish.httpsenabled
        Whether or not to listen for HTTPS connections
  -sish.httpspems string
        The location of pem files for HTTPS (fullchain.pem and privkey.pem) (default "ssl/")
  -sish.keysdir string
        Directory for public keys for pubkey auth (default "pubkeys/")
  -sish.password string
        Password to use for password auth (default "S3Cr3tP4$$W0rD")
  -sish.pkloc string
        SSH server private key (default "keys/ssh_key")
  -sish.pkpass string
        Passphrase to use for the server private key (default "S3Cr3tP4$$phrAsE")
  -sish.subdomainlen int
        The length of the random subdomain to generate (default 3)
```