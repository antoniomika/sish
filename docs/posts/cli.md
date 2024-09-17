---
title: CLI
description: How use sish's CLI 
keywords: [sish, cli]
---

```text
sish is a command line utility that implements an SSH server that can handle HTTP(S)/WS(S)/TCP multiplexing, forwarding and load balancing.
It can handle multiple vhosting and reverse tunneling endpoints for a large number of clients.

Usage:
  sish [flags]

Flags:
      --admin-console                                           Enable the admin console accessible at http(s)://domain/_sish/console?x-authorization=admin-console-token
  -j, --admin-console-token string                              The token to use for admin console access if it's enabled
      --alias-load-balancer                                     Enable the alias load balancer (multiple clients can bind the same alias)
      --append-user-to-subdomain                                Append the SSH user to the subdomain. This is useful in multitenant environments
      --append-user-to-subdomain-separator string               The token to use for separating username and subdomain selection in a virtualhost (default "-")
      --authentication                                          Require authentication for the SSH service (default true)
      --authentication-key-request-timeout duration             Duration to wait for a response from the authentication key request (default 5s)
      --authentication-key-request-url string                   A url to validate public keys for public key authentication.
                                                                sish will make an HTTP POST request to this URL with a JSON body containing an
                                                                OpenSSH 'authorized key' formatted public key, username,
                                                                and ip address. E.g.:
                                                                {"auth_key": string, "user": string, "remote_addr": string}
                                                                A response with status code 200 indicates approval of the auth key
  -k, --authentication-keys-directory string                    Directory where public keys for public key authentication are stored.
                                                                sish will watch this directory and automatically load new keys and remove keys
                                                                from the authentication list (default "deploy/pubkeys/")
      --authentication-keys-directory-watch-interval duration   The interval to poll for filesystem changes for SSH keys (default 200ms)
  -u, --authentication-password string                          Password to use for SSH server password authentication
      --authentication-password-request-timeout duration        Duration to wait for a response from the authentication password request (default 5s)
      --authentication-password-request-url string              A url to validate passwords for password-based authentication.
                                                                sish will make an HTTP POST request to this URL with a JSON body containing
                                                                the provided password, username, and ip address. E.g.:
                                                                {"password": string, "user": string, "remote_addr": string}
                                                                A response with status code 200 indicates approval of the password
      --banned-aliases string                                   A comma separated list of banned aliases that users are unable to bind
  -o, --banned-countries string                                 A comma separated list of banned countries. Applies to HTTP, TCP, and SSH connections
  -x, --banned-ips string                                       A comma separated list of banned ips that are unable to access the service. Applies to HTTP, TCP, and SSH connections
  -b, --banned-subdomains string                                A comma separated list of banned subdomains that users are unable to bind (default "localhost")
      --bind-any-host                                           Allow binding any host when accepting an HTTP listener
      --bind-hosts string                                       A comma separated list of other hosts a user can bind. Requested hosts should be subdomains of a host in this list
      --bind-http-auth                                          Allow binding http auth on a forwarded host (default true)
      --bind-http-path                                          Allow binding specific paths on a forwarded host (default true)
      --bind-random-aliases                                     Force bound alias tunnels to use random aliases instead of user provided ones (default true)
      --bind-random-aliases-length int                          The length of the random alias to generate if a alias is unavailable or if random aliases are enforced (default 3)
      --bind-random-ports                                       Force TCP tunnels to bind a random port, where the kernel will randomly assign it (default true)
      --bind-random-subdomains                                  Force bound HTTP tunnels to use random subdomains instead of user provided ones (default true)
      --bind-random-subdomains-length int                       The length of the random subdomain to generate if a subdomain is unavailable or if random subdomains are enforced (default 3)
      --bind-root-domain                                        Allow binding the root domain when accepting an HTTP listener
      --bind-wildcards                                          Allow binding wildcards when accepting an HTTP listener
      --cleanup-unauthed                                        Cleanup unauthed SSH connections after a set timeout (default true)
      --cleanup-unauthed-timeout duration                       Duration to wait before cleaning up an unauthed connection (default 5s)
      --cleanup-unbound                                         Cleanup unbound (unforwarded) SSH connections after a set timeout
      --cleanup-unbound-timeout duration                        Duration to wait before cleaning up an unbound (unforwarded) connection (default 5s)
  -c, --config string                                           Config file (default "config.yml")
      --debug                                                   Enable debugging information
      --debug-interval duration                                 Duration to wait between each debug loop output if debug is true (default 2s)
  -d, --domain string                                           The root domain for HTTP(S) multiplexing that will be appended to subdomains (default "ssi.sh")
      --force-all-https                                         Redirect all requests to the https server
      --force-https                                             Allow indiviual binds to request for https to be enforced
      --force-requested-aliases                                 Force the aliases used to be the one that is requested. Will fail the bind if it exists already
      --force-requested-ports                                   Force the ports used to be the one that is requested. Will fail the bind if it exists already
      --force-requested-subdomains                              Force the subdomains used to be the one that is requested. Will fail the bind if it exists already
      --force-tcp-address                                       Force the address used for the TCP interface to be the one defined by --tcp-address
      --geodb                                                   Use a geodb to verify country IP address association for IP filtering
  -h, --help                                                    help for sish
  -i, --http-address string                                     The address to listen for HTTP connections (default "localhost:80")
      --http-load-balancer                                      Enable the HTTP load balancer (multiple clients can bind the same domain)
      --http-port-override int                                  The port to use for http command output. This does not affect ports used for connecting, it's for cosmetic use only
      --http-request-port-override int                          The port to use for http requests. Will default to 80, then http-port-override. Otherwise will use this value
      --https                                                   Listen for HTTPS connections. Requires a correct --https-certificate-directory
  -t, --https-address string                                    The address to listen for HTTPS connections (default "localhost:443")
  -s, --https-certificate-directory string                      The directory containing HTTPS certificate files (name.crt and name.key). There can be many crt/key pairs (default "deploy/ssl/")
      --https-certificate-directory-watch-interval duration     The interval to poll for filesystem changes for HTTPS certificates (default 200ms)
      --https-ondemand-certificate                              Enable retrieving certificates on demand via Let's Encrypt
      --https-ondemand-certificate-accept-terms                 Accept the Let's Encrypt terms
      --https-ondemand-certificate-email string                 The email to use with Let's Encrypt for cert notifications. Can be left blank
      --https-port-override int                                 The port to use for https command output. This does not affect ports used for connecting, it's for cosmetic use only
      --https-request-port-override int                         The port to use for https requests. Will default to 443, then https-port-override. Otherwise will use this value
      --idle-connection                                         Enable connection idle timeouts for reads and writes (default true)
      --idle-connection-timeout duration                        Duration to wait for activity before closing a connection for all reads and writes (default 5s)
      --load-templates                                          Load HTML templates. This is required for admin/service consoles (default true)
      --load-templates-directory string                         The directory and glob parameter for templates that should be loaded (default "templates/*")
      --localhost-as-all                                        Enable forcing localhost to mean all interfaces for tcp listeners (default true)
      --log-to-client                                           Enable logging HTTP and TCP requests to the client
      --log-to-file                                             Enable writing log output to file, specified by log-to-file-path
      --log-to-file-compress                                    Enable compressing log output files
      --log-to-file-max-age int                                 The maxium number of days to store log output in a file (default 28)
      --log-to-file-max-backups int                             The maxium number of rotated logs files to keep (default 3)
      --log-to-file-max-size int                                The maximum size of outputed log files in megabytes (default 500)
      --log-to-file-path string                                 The file to write log output to (default "/tmp/sish.log")
      --log-to-stdout                                           Enable writing log output to stdout (default true)
      --ping-client                                             Send ping requests to the underlying SSH client.
                                                                This is useful to ensure that SSH connections are kept open or close cleanly (default true)
      --ping-client-interval duration                           Duration representing an interval to ping a client to ensure it is up (default 5s)
      --ping-client-timeout duration                            Duration to wait for activity before closing a connection after sending a ping to a client (default 5s)
  -n, --port-bind-range string                                  Ports or port ranges that sish will allow to be bound when a user attempts to use TCP forwarding (default "0,1024-65535")
  -p, --private-key-passphrase string                           Passphrase to use to encrypt the server private key (default "S3Cr3tP4$$phrAsE")
  -l, --private-keys-directory string                           The location of other SSH server private keys. sish will add these as valid auth methods for SSH. Note, these need to be unencrypted OR use the private-key-passphrase (default "deploy/keys")
      --proxy-protocol                                          Use the proxy-protocol while proxying connections in order to pass-on IP address and port information
      --proxy-protocol-listener                                 Use the proxy-protocol to resolve ip addresses from user connections
      --proxy-protocol-policy string                            What to do with the proxy protocol header. Can be use, ignore, reject, or require (default "use")
      --proxy-protocol-timeout duration                         The duration to wait for the proxy proto header (default 200ms)
      --proxy-protocol-use-timeout                              Use a timeout for the proxy-protocol read
  -q, --proxy-protocol-version string                           What version of the proxy protocol to use. Can either be 1, 2, or userdefined.
                                                                If userdefined, the user needs to add a command to SSH called proxyproto=version (ie proxyproto=1) (default "1")
      --redirect-root                                           Redirect the root domain to the location defined in --redirect-root-location (default true)
  -r, --redirect-root-location string                           The location to redirect requests to the root domain
                                                                to instead of responding with a 404 (default "https://github.com/antoniomika/sish")
      --rewrite-host-header                                     Force rewrite the host header if the user provides host-header=host.com (default true)
      --service-console                                         Enable the service console for each service and send the info to connected clients
      --service-console-max-content-length int                  The max content length before we stop reading the response body (default -1)
  -m, --service-console-token string                            The token to use for service console access. Auto generated if empty for each connected tunnel
      --sni-load-balancer                                       Enable the SNI load balancer (multiple clients can bind the same SNI domain/port)
      --sni-proxy                                               Enable the use of SNI proxying
      --sni-proxy-https                                         Enable the use of SNI proxying on the HTTPS port
  -a, --ssh-address string                                      The address to listen for SSH connections (default "localhost:2222")
      --strip-http-path                                         Strip the http path from the forward (default true)
      --tcp-address string                                      The address to listen for TCP connections
      --tcp-aliases                                             Enable the use of TCP aliasing
      --tcp-aliases-allowed-users any                           Enable setting allowed users to access tcp aliases.
                                                                Can provide tcp-aliases-allowed-users in the ssh command set to a comma separated list of ssh fingerprints that can access an alias.
                                                                Provide any for all.
      --tcp-load-balancer                                       Enable the TCP load balancer (multiple clients can bind the same port)
      --time-format string                                      The time format to use for both HTTP and general log messages (default "2006/01/02 - 15:04:05")
      --verify-dns                                              Verify DNS information for hosts and ensure it matches a connecting users sha256 key fingerprint (default true)
      --verify-ssl                                              Verify SSL certificates made on proxied HTTP connections (default true)
  -v, --version                                                 version for sish
  -y, --whitelisted-countries string                            A comma separated list of whitelisted countries. Applies to HTTP, TCP, and SSH connections
  -w, --whitelisted-ips string                                  A comma separated list of whitelisted ips. Applies to HTTP, TCP, and SSH connections
```
