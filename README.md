# sish

An open source serveo/ngrok alternative.

## Deploy

Builds are made automatically for each commit to the repo and are pushed to Dockerhub. Builds are
tagged using a commit sha, branch name, tag, latest if released on master.
You can find a list [here](https://hub.docker.com/r/antoniomika/sish/tags).
Each release builds separate `sish` binaries that can be downloaded from
[here](https://github.com/antoniomika/sish/releases) for various OS/archs.
Feel free to either use the automated binaries or to build your own. If you submit a PR, images are
not built by default and will require a retag from a maintainer to be built.

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

## Docker Compose

You can also use Docker Compose to setup your sish instance. This includes taking
care of SSL via Let's Encrypt for you. This uses the
[adferrand/dnsrobocert](https://github.com/adferrand/dnsrobocert) container to handle issuing wildcard
certifications over DNS. For more information on how to use this, head to that link above. Generally, you
can deploy your service like so:

```bash
docker-compose -f deploy/docker-compose.yml up -d
```

The domain and DNS auth info in `deploy/docker-compose.yml` and `deploy/le-config.yml` should be updated
to reflect your needs. You will also need to create a symlink that points to your domain's
Let's Encrypt certificates like:

```bash
ln -s /etc/letsencrypt/live/<your domain>/fullchain.pem deploy/ssl/<your domain>.crt
ln -s /etc/letsencrypt/live/<your domain>/privkey.pem deploy/ssl/<your domain>.key
```

Careful: the symlinks need to point to `/etc/letsencrypt`, not a relative path. The symlinks will
not resolve on the host filesystem, but they will resolve inside of the sish container because it mounts
the letsencrypt files in /etc/letsencrypt, _not_ ./letsencrypt.

I use these files in my deployment of `ssi.sh` and have included them here for consistency.

## How it works

SSH can normally forward local and remote ports. This service implements
an SSH server that only handles forwarding and nothing else. The service supports
multiplexing connections over HTTP/HTTPS with WebSocket support. Just assign a
remote port as port `80` to proxy HTTP traffic and `443` to proxy HTTPS traffic.
If you use any other remote port, the server will listen to the port for TCP connections,
but only if that port is available.

You can choose your own subdomain instead of relying on a randomly assigned one
by setting the `--bind-random-subdomains` option to `false` and then selecting a
subdomain by prepending it to the remote port specifier:

`ssh -p 2222 -R foo:80:localhost:8080 ssi.sh`

If the selected subdomain is not taken, it will be assigned to your connection.

## Supported forwarding types

### HTTP forwarding

sish can forward any number of HTTP connections through SSH. It also provides logging the connections
to the connected client that has forwarded the connection and a web interface to see full request and
responses made to each forwarded connection. Each webinterface can be unique to the forwarded connection or
use a unified access token. To make use of HTTP forwarding, ports `[80, 443]` are used to tell sish that a
HTTP connection is being forwarded and that HTTP virtualhosting should be defined for the service. For
example, let's say I'm
developing a HTTP webservice on my laptop at port `8080` that uses websockets and I want to show one of my
coworkers who is not near me. I can forward the connection like so:

```bash
ssh -R hereiam:80:localhost:8080 ssi.sh
```

And then share the link `https://hereiam.ssi.sh` with my coworker. They should be able to access the service
seamlessly over HTTPS, with full websocket support working fine. Let's say `hereiam.ssi.sh` isn't available,
then sish will generate a random subdomain and give that to me.

### TCP forwarding

Any TCP based service can be used with sish for TCP and alias forwarding. TCP forwarding
will establish a remote port on the server that you deploy sish to and will forward all connections
to that port through the SSH connection and to your local device. For example, if I was to run
a SSH server on my laptop with port `22` and want to be able to access it from anywhere at `ssi.sh:2222`,
I can use an SSH command on my laptop like so to forward the connection:

```bash
ssh -R 2222:localhost:22 ssi.sh
```

I can use the forwarded connection to then access my laptop from anywhere:

```bash
ssh -p 2222 ssi.sh
```

### TCP alias forwarding

Let's say instead I don't want the service to be accessible by the rest of the world, you can then use a TCP
alias. A TCP alias is a type of forwarded TCP connection that only exists inside of sish. You can gain access
to the alias by using SSH with the `-W` flag, which will forwarding the SSH process' stdin/stdout to the
fowarded TCP connection. In combination with authentication, this will guarantee your remote service is safe
from the rest of the world because you need to login to sish before you can access it. Changing the example
above for this would mean running the following command on my laptop:

```bash
ssh -R mylaptop:22:localhost:22 ssi.sh
```

sish won't publish port 22 or 2222 to the rest of the world anymore, instead it'll retain a pointer saying
that TCP connections made from within SSH after a user has authenticated to `mylaptop:22` should be
forwarded to the forwarded TCP tunnel. Then I can use the forwarded connection access my laptop from
anywhere using:

```bash
ssh -o ProxyCommand="ssh -W %h:%p ssi.sh" mylaptop
```

Shorthand for which is this with newer SSH versions:

```bash
ssh -J ssi.sh mylaptop
```

## Authentication

If you want to use this service privately, it supports both public key and password
authentication. To enable authentication, set `--authentication=true` as one of your CLI
options and be sure to configure `--authentication-password` or `--authentication-keys-directory` to your
liking. The directory provided by `--authentication-keys-directory` is watched for changes and will reload
the authorized keys automatically. The authorized cert index is regenerated on directory
modification, so removed public keys will also automatically be removed. Files in this
directory can either be single key per file, or multiple keys per file separated by newlines,
similar to `authorized_keys`. Password auth can be disabled by setting `--authentication-password=""` as a
CLI option.

One of my favorite ways of using this for authentication is like so:

```bash
sish@sish0:~/sish/pubkeys# curl https://github.com/antoniomika.keys > antoniomika
```

This will load my public keys from GitHub, place them in the directory that sish is watching,
and then load the pubkey. As soon as this command is run, I can SSH normally and it will authorize me.

## Custom domains

sish supports allowing users to bring custom domains to the service, but SSH key auth is required to be
enabled. To use this feature, you must setup TXT and CNAME/A records for the domain/subdomain you would
like to use for your forwarded connection. The CNAME/A record must point to the domain or IP that is hosting
sish. The TXT record must be be a `key=val` string that looks like:

```text
sish=SSHKEYFINGERPRINT
```

Where `SSHKEYFINGERPRINT` is the fingerprint of the key used for logging into the server. You can set
multiple TXT records and sish will check all of them to ensure at least one is a match. You can retrieve
your key fingerprint by running:

```bash
ssh-keygen -lf ~/.ssh/id_rsa | awk '{print $2}'
```

If you trust the users connecting to sish and would like to allow any domain to be used with sish
(bypassing verification), there are a few added flags to aid in this. This is especially useful when
adding multiple wildcard certificates to sish in order to not need to automatically provision Let's
Encrypt certs. To disable verfication, set `--bind-any-host=true`, which will allow and subdomain/domain
combination to be used. To only allow subdomains of a certain subset of domains, you can set `--bind-hosts`
to a comma separated list of domains that are allowed to be bound.

To add certficates for sish to use, configure the `--https-certificate-directory` flag to point to a dir
that is accessible by sish. In the directory, sish will look for a combination of files that look like
`name.crt` and `name.key`. `name` can be arbitrary in either case, it just needs to be unique to the cert
and key pair to allow them to be loaded into sish.

## Load balancing

sish can load balance any type of forwarded connection, but this needs to be enabled when starting sish
using the `--http-load-balancer`,
`--tcp-load-balancer`, and `--alias-load-balancer` flags. Let's say you have a few edge nodes
(raspberry pis) that are running a service internally but you want to be able to balance load across these
devices from the outside world. By enabling load balancing in sish, this happens automatically when a
device with the same forwarded TCP port, alias, or HTTP subdomain connects to sish. Connections will then be
evenly distributed to whatever nodes are connected to sish that match the forwarded connection.

## Whitelisting IPs

Whitelisting IP ranges or countries is also possible. Whole CIDR ranges can be
specified with the `--whitelisted-ips` option that accepts a comma-separated
string like "192.30.252.0/22,185.199.108.0/22". If you want to whitelist a single
IP, use the `/32` range.

To whitelist countries, use `--whitelisted-countries` with a comma-separated
string of countries in ISO format (for example, "pt" for Portugal). You'll also
need to set `--geodb` to `true`.

## DNS Setup

To use sish, you need to add a wildcard DNS record that is used for multiplexed subdomains.
Adding an `A` record with `*` as the subdomain to the IP address of your server is the simplest way to achieve this configuration.


## Demo - At this time, the demo instance has been set to require auth due to abuse

There is a demo service (and my private instance) currently running on `ssi.sh` that
doesn't require any authentication. This service provides default logging
(errors, connection IP/username, and pubkey fingerprint). I do not log any of the password
authentication data or the data sent within the service/tunnels. My deploy uses the exact
deploy steps that are listed above. This instance is for testing and educational purposes only.
You can deploy this extremely easily on any host (Google Cloud Platform provides an always-free
instance that this should run perfectly on). If the service begins to accrue a lot of traffic,
I will enable authentication and then you can reach out to me to get your SSH key whitelisted
(make sure it's on GitHub and you provide me with your GitHub username).

## Notes

1. This is by no means production ready in any way. This was hacked together and solves a fairly specific
use case.
      - You can help it get production ready by submitting PRs/reviewing code/writing tests/etc
2. This is a fairly simple implementation, I've intentionally cut corners in some places to make it easier
to write.
3. If you have any questions or comments, feel free to reach out via email
[me@antoniomika.me](mailto:me@antoniomika.me)
or on [freenode IRC #sish](https://kiwiirc.com/client/chat.freenode.net:6697/#sish)

## Upgrading to v1.0

There are numerous breaking changes in sish between pre-1.0 and post-1.0 versions. The largest changes are
found in the mapping of command flags and configuration params. Those have changed drastically, but it should be easy
to find the new counterpart. The other change is SSH keys that are supported for host key auth. sish
continues to support most modern keys, but by default if a host key is not found, it will create an OpenSSH
ED25519 key to use. Previous versions of sish would aes encrypt the pem block of this private key, but we
have since moved to using the native
[OpenSSH private key format](https://github.com/openssh/openssh-portable/blob/master/sshkey.c) to allow for
easy interop between OpenSSH tools. For this reason, you will either have to manually convert an AES
encrypted key or generate a new one.

## CLI Flags

```text
sish is a command line utility that implements an SSH server that can handle HTTP(S)/WS(S)/TCP multiplexing, forwarding and load balancing.
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
      --banned-aliases string                       A comma separated list of banned aliases that users are unable to bind
  -o, --banned-countries string                     A comma separated list of banned countries. Applies to HTTP, TCP, and SSH connections
  -x, --banned-ips string                           A comma separated list of banned ips that are unable to access the service. Applies to HTTP, TCP, and SSH connections
  -b, --banned-subdomains string                    A comma separated list of banned subdomains that users are unable to bind (default "localhost")
      --bind-any-host                               Bind any host when accepting an HTTP listener
      --bind-hosts string                           A comma separated list of other hosts a user can bind. Requested hosts should be subdomains of a host in this list
      --bind-random-aliases                         Force bound alias tunnels to use random aliases instead of user provided ones (default true)
      --bind-random-aliases-length int              The length of the random alias to generate if a alias is unavailable or if random aliases are enforced (default 3)
      --bind-random-ports                           Force TCP tunnels to bind a random port, where the kernel will randomly assign it (default true)
      --bind-random-subdomains                      Force bound HTTP tunnels to use random subdomains instead of user provided ones (default true)
      --bind-random-subdomains-length int           The length of the random subdomain to generate if a subdomain is unavailable or if random subdomains are enforced (default 3)
      --cleanup-unbound                             Cleanup unbound (unforwarded) SSH connections after a set timeout (default true)
      --cleanup-unbound-timeout duration            Duration to wait before cleaning up an unbound (unforwarded) connection (default 5s)
  -c, --config string                               Config file (default "config.yml")
      --debug                                       Enable debugging information
  -d, --domain string                               The root domain for HTTP(S) multiplexing that will be appended to subdomains (default "ssi.sh")
      --force-requested-aliases                     Force the aliases used to be the one that is requested. Will fail the bind if it exists already
      --force-requested-ports                       Force the ports used to be the one that is requested. Will fail the bind if it exists already
      --force-requested-subdomains                  Force the subdomains used to be the one that is requested. Will fail the bind if it exists already
      --geodb                                       Use a geodb to verify country IP address association for IP filtering
  -h, --help                                        help for sish
  -i, --http-address string                         The address to listen for HTTP connections (default "localhost:80")
      --http-load-balancer                          Enable the HTTP load balancer (multiple clients can bind the same domain)
      --http-port-override int                      The port to use for http command output. This does not effect ports used for connecting, it's for cosmetic use only
      --https                                       Listen for HTTPS connections. Requires a correct --https-certificate-directory
  -t, --https-address string                        The address to listen for HTTPS connections (default "localhost:443")
  -s, --https-certificate-directory string          The directory containing HTTPS certificate files (name.crt and name.key). There can be many crt/key pairs (default "deploy/ssl/")
      --https-ondemand-certificate                  Enable retrieving certificates on demand via Let's Encrypt
      --https-ondemand-certificate-accept-terms     Accept the Let's Encrypt terms
      --https-ondemand-certificate-email string     The email to use with Let's Encrypt for cert notifications. Can be left blank
      --https-port-override int                     The port to use for https command output. This does not effect ports used for connecting, it's for cosmetic use only
      --idle-connection                             Enable connection idle timeouts for reads and writes (default true)
      --idle-connection-timeout duration            Duration to wait for activity before closing a connection for all reads and writes (default 5s)
      --load-templates                              Load HTML templates. This is required for admin/service consoles (default true)
      --load-templates-directory string             The directory and glob parameter for templates that should be loaded (default "templates/*")
      --localhost-as-all                            Enable forcing localhost to mean all interfaces for tcp listeners (default true)
      --log-to-client                               Enable logging HTTP and TCP requests to the client
      --log-to-file                                 Enable writing log output to file, specified by log-to-file-path
      --log-to-file-compress                        Enable compressing log output files
      --log-to-file-max-age int                     The maxium number of days to store log output in a file (default 28)
      --log-to-file-max-backups int                 The maxium number of rotated logs files to keep (default 3)
      --log-to-file-max-size int                    The maximum size of outputed log files in megabytes (default 500)
      --log-to-file-path string                     The file to write log output to (default "/tmp/sish.log")
      --log-to-stdout                               Enable writing log output to stdout (default true)
      --ping-client                                 Send ping requests to the underlying SSH client.
                                                    This is useful to ensure that SSH connections are kept open or close cleanly (default true)
      --ping-client-interval duration               Duration representing an interval to ping a client to ensure it is up (default 5s)
      --ping-client-timeout duration                Duration to wait for activity before closing a connection after sending a ping to a client (default 5s)
  -n, --port-bind-range string                      Ports or port ranges that sish will allow to be bound when a user attempts to use TCP forwarding (default "0,1024-65535")
  -l, --private-key-location string                 The location of the SSH server private key. sish will create a private key here if
                                                    it doesn't exist using the --private-key-passphrase to encrypt it if supplied (default "deploy/keys/ssh_key")
  -p, --private-key-passphrase string               Passphrase to use to encrypt the server private key (default "S3Cr3tP4$$phrAsE")
      --proxy-protocol                              Use the proxy-protocol while proxying connections in order to pass-on IP address and port information
      --proxy-protocol-listener                     Use the proxy-protocol to resolve ip addresses from user connections
      --proxy-protocol-policy string                What to do with the proxy protocol header. Can be use, ignore, reject, or require (default "use")
      --proxy-protocol-timeout duration             The duration to wait for the proxy proto header (default 200ms)
      --proxy-protocol-use-timeout                  Use a timeout for the proxy-protocol read
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
      --time-format string                          The time format to use for both HTTP and general log messages (default "2006/01/02 - 15:04:05")
      --verify-dns                                  Verify DNS information for hosts and ensure it matches a connecting users sha256 key fingerprint (default true)
      --verify-ssl                                  Verify SSL certificates made on proxied HTTP connections (default true)
  -v, --version                                     version for sish
  -y, --whitelisted-countries string                A comma separated list of whitelisted countries. Applies to HTTP, TCP, and SSH connections
  -w, --whitelisted-ips string                      A comma separated list of whitelisted ips. Applies to HTTP, TCP, and SSH connections
```
