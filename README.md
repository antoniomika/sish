sish
====

An open source serveo/ngrok alternative.

Deploy
------

Builds are made automatically on Google Cloud Build and Dockerhub. Feel free to
either use the automated binaries or to build your own. If you submit a PR and
would like access to Google Cloud Build's output (including pre-made PR binaries), feel free to let me know.

1. Pull the Docker image
    - `docker pull antoniomika/sish:latest`
2. Run the image

    - ```bash
      docker run -itd --name sish \
        -v ~/sish/ssl:/ssl \
        -v ~/sish/keys:/keys \
        -v ~/sish/pubkeys:/pubkeys \
        --net=host antoniomika/sish:latest \
        --ssh-address=:22 \
        --http-address=:80 \
        --https-address=:443 \
        --enable-https=true \
        --certificate-directory=/ssl \
        --authentication-keys-directory=/pubkeys \
        --private-key-location=/keys/ssh_key \
        --bind-random-ports=false
      ```

3. SSH to your host to communicate with sish
    - `ssh -p 2222 -R 80:localhost:8080 ssi.sh`

Docker Compose
--------------

You can also use Docker Compose to setup your sish instance. This includes taking
care of SSL via Let's Encrypt for you. This uses the [adferrand/dnsrobocert](https://github.com/adferrand/dnsrobocert)
container to handle issuing wildcard certifications over DNS.
For more information on how to use this, head to that link above. Generally, you can deploy your service like so:

```bash
docker-compose -f deploy/docker-compose.yml up -d
```

The domain and DNS auth info in `deploy/docker-compose.yml` and `deploy/le-config.yml` should be updated
to reflect your needs. I use these files in my deployment of `ssi.sh` using git-ops.

How it works
------------

SSH can normally forward local and remote ports. This service implements
an SSH server that only does that and nothing else. The service supports
multiplexing connections over HTTP/HTTPS with WebSocket support. Just assign a
remote port as port `80` to proxy HTTP traffic and `443` to proxy HTTPS traffic.
If you use any other remote port, the server will listen to the port for connections,
but only if that port is available.

You can choose your own subdomain instead of relying on a randomly assigned one
by setting the `--bind-random-subdomains` option to `false` and then selecting a
subdomain by prepending it to the remote port specifier:

`ssh -p 2222 -R foo:80:localhost:8080 ssi.sh`

If the selected subdomain is not taken, it will be assigned to your connection.

Authentication
--------------

If you want to use this service privately, it supports both public key and password
authentication. To enable authentication, set `--enable-authentication=true` as one of your CLI
options and be sure to configure `--authentication-password` or `--authentication-keys-directory` to your liking.
The directory provided by `--authentication-keys-directory` is watched for changes and will reload the
authorized keys automatically. The authorized cert index is regenerated on directory
modification, so removed public keys will also automatically be removed. Files in this
directory can either be single key per file, or multiple keys per file separated by newlines,
similar to `authorized_keys`. Password auth can be disabled by setting `--authentication-password=""` as a CLI option.

One of my favorite ways of using this for authentication is like so:

```bash
sish@sish0:~/sish/pubkeys# curl https://github.com/antoniomika.keys > antoniomika
```

This will load my public keys from GitHub, place them in the directory that sish is watching,
and then load the pubkey. As soon as this command is run, I can SSH normally and it will authorize me.

Whitelisting IPs
----------------

Whitelisting IP ranges or countries is also possible. Whole CIDR ranges can be
specified with the `--whitelisted-ips` option that accepts a comma-separated
string like "192.30.252.0/22,185.199.108.0/22". If you want to whitelist a single
IP, use the `/32` range.

To whitelist countries, use `--whitelisted-countries` with a comma-separated
string of countries in ISO format (for example, "pt" for Portugal). You'll also
need to set `--enable-geodb` to `true`.

Demo - At this time, the demo instance has been set to require auth due to abuse
----

There is a demo service (and my private instance) currently running on `ssi.sh` that
doesn't require any authentication. This service provides default logging
(errors, connection IP/username, and pubkey fingerprint). I do not log any of the password
authentication data or the data sent within the service/tunnels. My deploy uses the exact
deploy steps that are listed above. This instance is for testing and educational purposes only.
You can deploy this extremely easily on any host (Google Cloud Platform provides an always-free
instance that this should run perfectly on). If the service begins to accrue a lot of traffic,
I will enable authentication and then you can reach out to me to get your SSH key whitelisted
(make sure it's on GitHub and you provide me with your GitHub username).

Notes
-----

1. This is by no means production ready in any way. This was hacked together and solves a fairly specific use case.
      - You can help it get production ready by submitting PRs/reviewing code/writing tests/etc
2. This is a fairly simple implementation, I've intentionally cut corners in some places to make it easier to write.
3. If you have any questions or comments, feel free to reach out via email [me@antoniomika.me](mailto:me@antoniomika.me) or on [freenode IRC #sish](https://kiwiirc.com/client/chat.freenode.net:6697/#sish)

CLI Flags
---------

```text
sish is a command line utility that implements an SSH server
that can handle HTTP(S)/WS(S)/TCP multiplexing and forwarding.
It can handle multiple vhosting and reverse tunneling.

Usage:
  sish [flags]

Flags:
  -j, --admin-console-token string             The token to use for admin access (default "S3Cr3tP4$$W0rD")
      --append-user-to-subdomain               Whether or not to append the user to the subdomain
  -k, --authentication-keys-directory string   Directory for public keys for pubkey auth (default "deploy/pubkeys/")
  -u, --authentication-password string         Password to use for password auth (default "S3Cr3tP4$$W0rD")
  -o, --banned-countries string                A comma separated list of banned countries
  -x, --banned-ips string                      A comma separated list of banned ips
  -b, --banned-subdomains string               A comma separated list of banned subdomains (default "localhost")
      --bind-random-ports                      Bind ports randomly (OS chooses) (default true)
      --bind-random-subdomains                 Whether or not to force a random subdomain (default true)
  -s, --certificate-directory string           The location of pem files for HTTPS (fullchain.pem and privkey.pem) (default "deploy/ssl/")
      --cleanup-unbound                        Whether or not to cleanup unbound (forwarded) SSH connections (default true)
      --cleanup-unbound-timeout duration       Interval in seconds to wait before cleaning up an unbound connection. (default 5s)
  -c, --config string                          Config file (default "config.yml")
      --connection-idle-timeout duration       Number of seconds to wait for activity before closing a connection (default 5s)
      --debug                                  Whether or not to print debug information
  -d, --domain string                          The domain for HTTP(S) multiplexing (default "ssi.sh")
      --enable-admin-console                   Whether or not to enable the admin console
      --enable-authentication                  Whether or not to require auth on the SSH service
      --enable-geodb                           Whether or not to use the maxmind geodb
      --enable-https                           Whether or not to listen for HTTPS connections
      --enable-log-to-client                   Whether or not to log http requests to the client
      --enable-proxy-protocol                  Whether or not to enable the use of the proxy protocol
      --enable-redirect-root                   Whether or not to redirect the root domain (default true)
      --enable-service-console                 Whether or not to enable the admin console for each service and send the info to users
      --enable-tcp-aliases                     Whether or not to allow the use of TCP aliasing
  -h, --help                                   help for sish
  -i, --http-address string                    The address to listen for HTTP connections (default "localhost:80")
      --http-port-override int                 The port to use for http command output
  -t, --https-address string                   The address to listen for HTTPS connections (default "localhost:443")
      --https-port-override int                The port to use for https command output
      --max-subdomain-length int               The length of the random subdomain to generate (default 3)
      --ping-client                            Whether or not ping the client. (default true)
      --ping-client-interval duration          Interval in seconds to ping a client to ensure it is up. (default 5s)
  -n, --port-bind-range string                 Ports that are allowed to be bound (default "0,1024-65535")
  -l, --private-key-location string            SSH server private key (default "deploy/keys/ssh_key")
  -p, --private-key-passphrase string          Passphrase to use for the server private key (default "S3Cr3tP4$$phrAsE")
  -q, --proxy-protocol-version string          What version of the proxy protocol to use.
                                               Can either be 1, 2, or userdefined. If userdefined, the user needs to add a command
                                               to SSH called proxyproto:version (ie proxyproto:1) (default "1")
  -r, --redirect-root-location string          Where to redirect the root domain to (default "https://github.com/antoniomika/sish")
  -m, --service-console-token string           The token to use for service access. Auto generated if empty.
  -a, --ssh-address string                     The address to listen for SSH connections (default "localhost:2222")
      --user-subdomain-separator string        The token to use for separating username and subdomains in a virtualhost.
      --verify-origin                          Whether or not to verify origin on websocket connection (default true)
      --verify-ssl                             Whether or not to verify SSL on proxy connection (default true)
  -v, --version                                version for sish
  -y, --whitelisted-countries string           A comma separated list of whitelisted countries
  -w, --whitelisted-ips string                 A comma separated list of whitelisted ips
```
