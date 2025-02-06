---
title: Forwarding Types
description: The various forwarding types sish supports
keywords: [sish, forwarding, types, http, tcp, sni, alias]
---

# HTTP

sish can forward any number of HTTP connections through SSH. It also provides
logging the connections to the connected client that has forwarded the
connection and a web interface to see full request and responses made to each
forwarded connection. Each webinterface can be unique to the forwarded
connection or use a unified access token. To make use of HTTP forwarding, ports
`[80, 443]` are used to tell sish that a HTTP connection is being forwarded and
that HTTP virtualhosting should be defined for the service. For example, let's
say I'm developing a HTTP webservice on my laptop at port `8080` that uses
websockets and I want to show one of my coworkers who is not near me. I can
forward the connection like so:

```bash
ssh -R hereiam:80:localhost:8080 tuns.sh
```

And then share the link `https://hereiam.tuns.sh` with my coworker. They should
be able to access the service seamlessly over HTTPS, with full websocket support
working fine. Let's say `hereiam.tuns.sh` isn't available, then sish will
generate a random subdomain and give that to me.

# TCP

Any TCP based service can be used with sish for TCP and alias forwarding. TCP
forwarding will establish a remote port on the server that you deploy sish to
and will forward all connections to that port through the SSH connection and to
your local device. For example, if I was to run a SSH server on my laptop with
port `22` and want to be able to access it from anywhere at `tuns.sh:2222`, I
can use an SSH command on my laptop like so to forward the connection:

```bash
ssh -R 2222:localhost:22 tuns.sh
```

I can use the forwarded connection to then access my laptop from anywhere:

```bash
ssh -p 2222 tuns.sh
```

# TCP Alias

Let's say instead I don't want the service to be accessible by the rest of the
world, you can then use a TCP alias. A TCP alias is a type of forwarded TCP
connection that only exists inside of sish. You can gain access to the alias by
using SSH with the `-W` flag, which will forwarding the SSH process'
stdin/stdout to the forwarded TCP connection. In combination with authentication,
this will guarantee your remote service is safe from the rest of the world
because you need to login to sish before you can access it. Changing the example
above for this would mean running the following command on my laptop:

```bash
ssh -R mylaptop:22:localhost:22 tuns.sh
```

sish won't publish port 22 or 2222 to the rest of the world anymore, instead
it'll retain a pointer saying that TCP connections made from within SSH after a
user has authenticated to `mylaptop:22` should be forwarded to the forwarded TCP
tunnel. Then I can use the forwarded connection access my laptop from anywhere
using:

```bash
ssh -o ProxyCommand="ssh -W %h:%p tuns.sh" mylaptop
```

Shorthand for which is this with newer SSH versions:

```bash
ssh -J tuns.sh mylaptop
```

You can also use TCP aliases with any port you would like. If for example you
wanted to use an alias with port `80` or `443` (default to a HTTP tunnel),
provide the command `tcp-alias=true` to the ssh command:

```bash
ssh -R service:80:localhost:80 tuns.sh tcp-alias=true
```

Aliases can be accessed on a different computer using SSH local forwards also.
For the above, I could use:

```bash
ssh -L 80:service:80 tuns.sh
```

to then access the forwarded server service at `localhost:80` on the client side
of the computer I am on.

# SNI

Sometimes, you may have multiple TCP services running on the same port. If these
services support [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication),
you can have sish route TLS connections to different backends based on the SNI
name provided. For example, I have two webservices (servers) and I want to
offload TLS to each without sish offloading SSL. This can be achieved by
disabling sish's internal HTTPS service (you won't be able to use the service
console for this however). Then, I can start a ssh connection from each server
like so:

From server A

```bash
ssh -R servera.example.com:443:localhost:443 tuns.sh sni-proxy=true
```

From server B

```bash
ssh -R serverb.example.com:443:localhost:443 tuns.sh sni-proxy=true
```

As long as server{a,b}.example.com points to where sish is hosted and a user can
bind those hosts, TLS connections to servera.example.com:443 will be forwarded
to server A and TLS connections to serverb.example.com:443 will be forwarded to
server B. It is then up to each server to complete the TLS handshake and the
subsequent request.
