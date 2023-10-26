---
title: Advanced
description: How to customize sish
keywords: [sish, advanced, custom, domains, load, balancing, allowlist, ip]
---

# Choose your own subdomain

You can choose your own subdomain instead of relying on a randomly assigned one
by setting the `--bind-random-subdomains` option to `false` and then selecting a
subdomain by prepending it to the remote port specifier:

`ssh -p 2222 -R foo:80:localhost:8080 tuns.sh`

If the selected subdomain is not taken, it will be assigned to your connection.

# Websocket Support

The service supports multiplexing connections over HTTP/HTTPS with WebSocket
support. Just assign a remote port as port `80` to proxy HTTP traffic and `443`
to proxy HTTPS traffic. If you use any other remote port, the server will listen
to the port for TCP connections, but only if that port is available.

# Allowlist IPs

Whitelisting IP ranges or countries is also possible. Whole CIDR ranges can be
specified with the `--whitelisted-ips` option that accepts a comma-separated
string like "192.30.252.0/22,185.199.108.0/22". If you want to whitelist a
single IP, use the `/32` range.

To whitelist countries, use `--whitelisted-countries` with a comma-separated
string of countries in ISO format (for example, "pt" for Portugal). You'll also
need to set `--geodb` to `true`.

# Custom domains

sish supports allowing users to bring custom domains to the service, but SSH key
auth is required to be enabled. To use this feature, you must setup TXT and
CNAME/A records for the domain/subdomain you would like to use for your
forwarded connection. The CNAME/A record must point to the domain or IP that is
hosting sish. The TXT record must be be a `key=val` string that looks like:

```text
sish=SSHKEYFINGERPRINT
```

Where `SSHKEYFINGERPRINT` is the fingerprint of the key used for logging into
the server. You can set multiple TXT records and sish will check all of them to
ensure at least one is a match. You can retrieve your key fingerprint by
running:

```bash
ssh-keygen -lf ~/.ssh/id_rsa | awk '{print $2}'
```

If you trust the users connecting to sish and would like to allow any domain to
be used with sish (bypassing verification), there are a few added flags to aid
in this. This is especially useful when adding multiple wildcard certificates to
sish in order to not need to automatically provision Let's Encrypt certs. To
disable verfication, set `--bind-any-host=true`, which will allow and
subdomain/domain combination to be used. To only allow subdomains of a certain
subset of domains, you can set `--bind-hosts` to a comma separated list of
domains that are allowed to be bound.

To add certficates for sish to use, configure the
`--https-certificate-directory` flag to point to a dir that is accessible by
sish. In the directory, sish will look for a combination of files that look like
`name.crt` and `name.key`. `name` can be arbitrary in either case, it just needs
to be unique to the cert and key pair to allow them to be loaded into sish.

# Load balancing

sish can load balance any type of forwarded connection, but this needs to be
enabled when starting sish using the `--http-load-balancer`,
`--tcp-load-balancer`, and `--alias-load-balancer` flags. Let's say you have a
few edge nodes (raspberry pis) that are running a service internally but you
want to be able to balance load across these devices from the outside world. By
enabling load balancing in sish, this happens automatically when a device with
the same forwarded TCP port, alias, or HTTP subdomain connects to sish.
Connections will then be evenly distributed to whatever nodes are connected to
sish that match the forwarded connection.
