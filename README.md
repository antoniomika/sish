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
        --https=true \
        --https-certificate-directory=/ssl \
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
authentication. To enable authentication, set `--authentication=true` as one of your CLI
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
need to set `--geodb` to `true`.

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
sish is a command line utility that implements an SSH server that can handle HTTP(S)/WS(S)/TCP multiplexing and forwarding.
It can handle multiple vhosting and reverse tunneling endpoints for a large number of clients.

Usage:
  sish [flags]

Flags:
      --admin-console                               Enable the admin console accessible at http(s)://domain/_sish/console?x-authorization=admin-console-token
  -j, --admin-console-token string                  The token to use for admin console access if it's enabled (default "S3Cr3tP4$$W0rD")
      --alias-load-balancer                         Enable the alias load balancer (multiple clients can bind the same alias)
      --append-user-to-subdomain                    Append the SSH user to the subdomain. This is useful in multitenant environments
      --append-user-to-subdomain-separator string   The token to use for separating username and subdomain selection in a virtualhost (default "-")
      --authentication                              Require authentication for the SSH service
  -k, --authentication-keys-directory string        Directory where public keys for public key authentication are stored.
                                                    sish will watch this directory and automatically load new keys and remove keys
                                                    from the authentication list (default "deploy/pubkeys/")
  -u, --authentication-password string              Password to use for ssh server password authentication (default "S3Cr3tP4$$W0rD")
  -o, --banned-countries string                     A comma separated list of banned countries. Applies to HTTP, TCP, and SSH connections
  -x, --banned-ips string                           A comma separated list of banned ips that are unable to access the service. Applies to HTTP, TCP, and SSH connections
  -b, --banned-subdomains string                    A comma separated list of banned subdomains that users are unable to bind (default "localhost")
      --bind-random-ports                           Force TCP tunnels to bind a random port, where the kernel will randomly assign it (default true)
      --bind-random-subdomains                      Force bound HTTP tunnels to use random subdomains instead of user provided ones (default true)
      --bind-random-subdomains-length int           The length of the random subdomain to generate if a subdomain is unavailable or if random subdomains are enforced (default 3)
      --cleanup-unbound                             Cleanup unbound (unforwarded) SSH connections after a set timeout (default true)
      --cleanup-unbound-timeout duration            Duration to wait before cleaning up an unbound (unforwarded) connection (default 5s)
  -c, --config string                               Config file (default "config.yml")
      --debug                                       Enable debugging information
  -d, --domain string                               The root domain for HTTP(S) multiplexing that will be appended to subdomains (default "ssi.sh")
      --geodb                                       Use a geodb to verify country IP address association for IP filtering
  -h, --help                                        help for sish
  -i, --http-address string                         The address to listen for HTTP connections (default "localhost:80")
      --http-load-balancer                          Enable the HTTP load balancer (multiple clients can bind the same domain)
      --http-port-override int                      The port to use for http command output. This does not effect ports used for connecting, it's for cosmetic use only
      --https                                       Listen for HTTPS connections. Requires a correct --https-certificate-directory
  -t, --https-address string                        The address to listen for HTTPS connections (default "localhost:443")
  -s, --https-certificate-directory string          The directory containing HTTPS certificate files (fullchain.pem and privkey.pem) (default "deploy/ssl/")
      --https-port-override int                     The port to use for https command output. This does not effect ports used for connecting, it's for cosmetic use only
      --idle-connection                             Enable connection idle timeouts for reads and writes (default true)
      --idle-connection-timeout duration            Duration to wait for activity before closing a connection for all reads and writes (default 5s)
      --localhost-as-all                            Enable forcing localhost to mean all interfaces for tcp listeners (default true)
      --log-to-client                               Enable logging HTTP and TCP requests to the client
      --ping-client                                 Send ping requests to the underlying SSH client.
                                                    This is useful to ensure that SSH connections are kept open or close cleanly (default true)
      --ping-client-interval duration               Duration representing an interval to ping a client to ensure it is up (default 5s)
      --ping-client-timeout duration                Duration to wait for activity before closing a connection after sending a ping to a client (default 5s)
  -n, --port-bind-range string                      Ports or port ranges that sish will allow to be bound when a user attempts to use TCP forwarding (default "0,1024-65535")
  -l, --private-key-location string                 The location of the SSH server private key. sish will create a private key here if
                                                    it doesn't exist using the --private-key-passphrase to encrypt it if supplied (default "deploy/keys/ssh_key")
  -p, --private-key-passphrase string               Passphrase to use to encrypt the server private key (default "S3Cr3tP4$$phrAsE")
      --proxy-protocol                              Use the proxy-protocol while proxying connections in order to pass-on IP address and port information
  -q, --proxy-protocol-version string               What version of the proxy protocol to use. Can either be 1, 2, or userdefined.
                                                    If userdefined, the user needs to add a command to SSH called proxyproto:version (ie proxyproto:1) (default "1")
      --redirect-root                               Redirect the root domain to the location defined in --redirect-root-location (default true)
  -r, --redirect-root-location string               The location to redirect requests to the root domain
                                                    to instead of responding with a 404 (default "https://github.com/antoniomika/sish")
      --service-console                             Enable the service console for each service and send the info to connected clients
  -m, --service-console-token string                The token to use for service console access. Auto generated if empty for each connected tunnel
  -a, --ssh-address string                          The address to listen for SSH connections (default "localhost:2222")
      --tcp-aliases                                 Enable the use of TCP aliasing
      --tcp-load-balancer                           Enable the TCP load balancer (multiple clients can bind the same port)
      --time-format string                          The time format to use for both HTTP and general log messages. (default "2006/01/02 - 15:04:05")
      --verify-dns                                  Verify DNS information for hosts and ensure it matches a connecting users sha256 key fingerprint (default true)
      --verify-ssl                                  Verify SSL certificates made on proxied HTTP connections (default true)
  -v, --version                                     version for sish
  -y, --whitelisted-countries string                A comma separated list of whitelisted countries. Applies to HTTP, TCP, and SSH connections
  -w, --whitelisted-ips string                      A comma separated list of whitelisted ips. Applies to HTTP, TCP, and SSH connections
```
