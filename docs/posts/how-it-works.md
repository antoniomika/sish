---
title: How it works
description: Technical details for sish 
keywords: [sish, how, works]
---

SSH can normally forward local and remote ports. This service implements an SSH
server that only handles forwarding and nothing else.

But let's first take a step back and illustrate some basic examples of how
things work without `sish`. Let's start with a simple port forward:

# Port Forward

Here Eric has a web server hosted on its `localhost:3000`. Eric has to forward
its localhost connection to Tony in order for him to access the web server.

<div class="hiw">
  <img src="./hiw-port-forward.png" alt="hiw-port-forward" />
</div>

This is manual, arduous, and sometimes difficult to get to work properly because
of firewalls. So many people opt to setup a VPN that both Eric and Tony can
connect to.

# Traditional VPN

Now both Eric and Tony connect to the VPN service and then Tony can access
Eric's web server via Eric's VPN IP.

<div class="hiw">
  <img src="./hiw-vpn.png" alt="hiw-vpn" />
</div>

Great! But this requires both Eric and Tony to connect to the VPN service. What
if Eric wants to share the web server with multiple users that are **not**
connected to the VPN? Sometimes it isn't feasible or appropriate to have
everyone connect to your VPN.

# sish Public

Enter `sish`. Using just SSH and a `sish` service, Eric can create an SSH remote
port forward to connect to `sish` which will automatically create a public URL
that **anyone** can access.

<div class="hiw">
  <img src="./hiw-sish-public.png" alt="hiw-sish-public" />
</div>

Very nice! Tony doesn't have to worry about firewall issues, setting up and
connecting to a VPN, and anyone else can also access the web server via URL.
This is the real power of leveraging `sish`.

But what if we want the web server to be private so only Tony can access the web
server using `sish`?

# sish Private

In this example both Eric and Tony setup an SSH tunnel to `sish`:

- Eric sets up a remote port forward tunnel
- Tony sets up a local port forward tunnel

<div class="hiw">
  <img src="./hiw-sish-private.png" alt="hiw-sish-private" />
</div>

> NOTE: The remote tunnel command needs to include `tcp-aliases-allowed` with
> Tony's pubkey fingerprint

```bash
ssh -R private:3000:localhost:3000 tuns.sh tcp-aliases-allowed-users=SHA256:4vNGm4xvuVxYbaIE5JX1KgTgncaF3x3w2lk+JMLOfd8
```

This creates a private connection between Eric and Tony that allows Tony to
access Eric's local web server without anyone else having access to it!

[Learn more](/cheatsheet#https-private-access)
