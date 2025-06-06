---
title: Cheatsheet
description: sish usage reference
keywords: [sish, reference, cheatsheet]
---

[More info about forwarding types](/forwarding-types)

# Remote forward SSH tunnels

Full example:

```bash
ssh -R subdomain:80:localhost:3000 tuns.sh
#  |__|
# remote forward

ssh -R subdomain:80:localhost:3000 tuns.sh
#     |_________|
#   subdomain.tuns.sh

ssh -R subdomain:80:localhost:3000 tuns.sh
#                  |______________|
#                  local web server
```

Dropping the subdomain:

```bash
ssh -R 80:localhost:3000 tuns.sh
#     |__|
# autogenerated.tuns.sh
# access local server over http (443 for https)

ssh -R 80:localhost:3000 tuns.sh
#        |______________|
# local web server over http
```

# Local forward SSH tunnels

Given remote forward to `subdomain.tuns.sh:80`

```bash
ssh -L 3000:subdomain:80 tuns.sh
#  |__|
# local forward

ssh -L 3000:subdomain:80 tuns.sh
#     |____|
# access tunnel at localhost:3000 

ssh -L 3000:subdomain:80 tuns.sh
#          |____________|
#       subdomain.tuns.sh:80
```

# HTTPS public access

[More info](/forwarding-types#http)

- Eric has a web server running on `localhost:3000`
- Eric wants to share with anyone
- Tony wants to access it

Eric sets up remote forward:

```bash
ssh -R 80:localhost:3000 tuns.sh
```

# HTTPS private access

- Eric has a web server running on `localhost:3000`
- Eric only wants to share with Tony
- Tony wants to access it

Tony provides Eric with pubkey fingerprint:

```bash
ssh-keygen -lf ~/.ssh/id_ed25519
256 SHA256:4vNGm4xvuVxYbaIE5JX1KgTgncaF3x3w2lk+JMLOfd8 your_email@example.com (ED25519)
```

Eric sets up remote forward using Tony's fingerprint:

```bash
ssh -R private:3000:localhost:3000 tuns.sh tcp-aliases-allowed-users=SHA256:4vNGm4xvuVxYbaIE5JX1KgTgncaF3x3w2lk+JMLOfd8
```

Tony sets up local forward:

```bash
ssh -L 3000:private:3000 tuns.sh
```

Tony can access site at `http://localhost:3000`

# Websocket

Same method as [HTTPS public access](/cheatsheet#https-public-access).

# TCP public access

Expose SSH to the world

```bash
ssh -R 2222:localhost:22 tuns.sh
```

I can use the forwarded connection to then access my laptop from anywhere:

```bash
ssh -p 2222 tuns.sh
```

# TCP private access

For example if you want to use `netcat` to send files between computers.

[Setup a TCP alias](/forwarding-types#tcp-alias)

# Setting a deadline for a tunnel

You can set a deadline for a tunnel after which the connection will automatically close.

The deadline can be relative:

```bash
ssh -R 80:localhost:3000 tuns.sh deadline=15m
```

Or it can be provided as an absolute [ISO-8601 time string](https://www.iso.org/iso-8601-date-and-time-format.html):

```bash
ssh -R 80:localhost:3000 tuns.sh deadline=2025-03-10T15:19:22
ssh -R 80:localhost:3000 tuns.sh deadline=2025-03-10T15:19:22Z
ssh -R 80:localhost:3000 tuns.sh deadline=2025-03-10T15:19:22-07:00
```

Or as an absolute [Unix epoch value](https://www.unixtimestamp.com/):

```bash
ssh -R 80:localhost:3000 tuns.sh deadline=1741614000
```
