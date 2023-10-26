---
title: Getting Started
description: Learn how to use sish 
keywords: [sish, guide, getting, started, how]
---

We have a managed service and **three** officially supported self-hosting
deployments for `sish`.

Here are the guides related to self-hosting `sish`.

# Managed

The easiest way to get started with using sish is to use our managed service at
[tuns.sh](https://tuns.sh). This service manages `sish` for you so you don't
have to go through the process of setting `sish` up yourself.

# DNS

To use sish, you need to add a wildcard DNS record that is used for multiplexed
subdomains. Adding an `A` record with `*` as the subdomain to the IP address of
your server is the simplest way to achieve this configuration.

For the purposes of our guides, we will use `tuns.sh` as our domain.

# Docker Compose

You can use Docker Compose to setup your sish instance. This includes taking
care of SSL via Let's Encrypt for you. This uses the
[adferrand/dnsrobocert](https://github.com/adferrand/dnsrobocert) container to
handle issuing wildcard certifications over DNS. For more information on how to
use this, head to that link above.

We use
[sish/deploy](https://github.com/antoniomika/sish/tree/4ed42082289f6da8a9f873ed8110963290ea4ce9/deploy)
in our deployment of `tuns.sh` and are using them for this guide.

Clone the `sish` repo:

```bash
git clone git@github.com:antoniomika/sish.git
```

Then copy the `sish/deploy` folder:

```bash
cp -R sish/deploy ~/sish
```

Edit `~/sish/docker-compose.yml` and `~/sish/le-config.yml` file with your
domain and DNS auth info.

Then, create a symlink that points to your domain's Let's Encrypt certificates
like:

```bash
ln -s /etc/letsencrypt/live/<your domain>/fullchain.pem deploy/ssl/<your domain>.crt
ln -s /etc/letsencrypt/live/<your domain>/privkey.pem deploy/ssl/<your domain>.key
```

> Careful: the symlinks need to point to `/etc/letsencrypt`, not a relative
> path. The symlinks will not resolve on the host filesystem, but they will
> resolve inside of the sish container because it mounts the letsencrypt files
> in /etc/letsencrypt, _not_ ./letsencrypt.

Finally, you can deploy your service like so:

```bash
docker-compose -f deploy/docker-compose.yml up -d
```

SSH to your host to communicate with sish

```bash
ssh -p 2222 -R 80:localhost:8080 tuns.sh
```

# Docker

[Find our latest releases.](/releases)

Pull the Docker image

```bash
docker pull antoniomika/sish:latest
```

Create folders to host your keys

```bash
mkdir -p ~/sish/ssl ~/sish/keys ~/sish/pubkeys
```

Copy your public keys to `pubkeys`

```bash
cp ~/.ssh/id_ed25519.pub ~/sish/pubkeys
```

Run the image

```bash
docker run -itd --name sish \
  -v ~/sish/ssl:/ssl \
  -v ~/sish/keys:/keys \
  -v ~/sish/pubkeys:/pubkeys \
  --net=host antoniomika/sish:latest \
  --ssh-address=:2222 \
  --http-address=:80 \
  --https-address=:443 \
  --https=true \
  --https-certificate-directory=/ssl \
  --authentication-keys-directory=/pubkeys \
  --private-keys-directory=/keys \
  --bind-random-ports=false \
  --domain=tuns.sh
```

SSH to your host to communicate with sish

```bash
ssh -p 2222 -R 80:localhost:8080 tuns.sh
```

# Google Cloud Platform

There is a tutorial for creating an instance in Google Cloud Platform with sish
fully setup that can be found
[here](https://github.com/antoniomika/sish/blob/main/deploy/gcloud.md). It can
be accessed through [Google Cloud Shell](https://cloud.google.com/shell).

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://ssh.cloud.google.com/cloudshell/editor?shellonly=true&cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fantoniomika%2Fsish&cloudshell_git_branch=main&cloudshell_tutorial=deploy%2Fgcloud.md)

# Authentication

If you want to use this service privately, it supports both public key and
password authentication. To enable authentication, set `--authentication=true`
as one of your CLI options and be sure to configure `--authentication-password`
or `--authentication-keys-directory` to your liking. The directory provided by
`--authentication-keys-directory` is watched for changes and will reload the
authorized keys automatically. The authorized cert index is regenerated on
directory modification, so removed public keys will also automatically be
removed. Files in this directory can either be single key per file, or multiple
keys per file separated by newlines, similar to `authorized_keys`. Password auth
can be disabled by setting `--authentication-password=""` as a CLI option.

One of my favorite ways of using this for authentication is like so:

```bash
sish@sish0:~/sish/pubkeys# curl https://github.com/antoniomika.keys > antoniomika
```

This will load my public keys from GitHub, place them in the directory that sish
is watching, and then load the pubkey. As soon as this command is run, I can SSH
normally and it will authorize me.
