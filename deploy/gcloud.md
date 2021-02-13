# sish installation

sish is an open source serveo/ngrok alternative that can be used to open a tunnel
to localhost that is accessible to the open internet using only SSH. sish implements
an SSH server that can handle multiplexing of HTTP(S), TCP, and TCP Aliasing
([more about this can be found in the README](https://github.com/antoniomika/sish/blob/main/README.md))

This tutorial will teach you how to:

* Setup an instance in Google Cloud using the [free tier](https://cloud.google.com/free)
* Change the default SSH port
* Add and modify authentication for users
* Access sish from a remote computer

## Project selection

You first need to select a project to host the resources created in this tutorial.
I'd suggest creating a new project at this time where your sish instance will live.
<walkthrough-project-setup></walkthrough-project-setup>

## Access Google Cloud Shell

<walkthrough-auto-open-cloud-shell></walkthrough-auto-open-cloud-shell>

## Create the instance running the container

Here is a command to create the instance running the sish container. This will start the container
on a hardened [Container Optimized OS](https://cloud.google.com/container-optimized-os/docs) and start
the service. This is just a starting command that runs sish on port `2222`, `80`, and `443`. If you
accept the [Let's Encrypt TOS](https://letsencrypt.org/repository/), you can enable automatic SSL cert loading.
This command does *NOT* include authentication and it is up to you to properly tune these parameters based on
the documentation [here](https://github.com/antoniomika/sish#cli-flags). Make sure to update `YOURDOMAIN`
to the actual domain you own. You will also need to setup the DNS records as described below. Also feel free
to change the `--zone` used for these commands.

```bash
gcloud compute instances create-with-container sish \
    --zone="us-central1-a" \
    --tags="sish" \
    --container-mount-host-path="host-path=/mnt/stateful_partition/sish/ssl,mount-path=/ssl" \
    --container-mount-host-path="host-path=/mnt/stateful_partition/sish/keys,mount-path=/keys" \
    --container-mount-host-path="host-path=/mnt/stateful_partition/sish/pubkeys,mount-path=/pubkeys" \
    --container-image="antoniomika/sish:latest" \
    --machine-type="f1-micro" \
    --container-arg="--domain=YOURDOMAIN" \
    --container-arg="--ssh-address=:2222" \
    --container-arg="--http-address=:80" \
    --container-arg="--https-address=:443" \
    --container-arg="--https=true" \
    --container-arg="--https-certificate-directory=/ssl" \
    --container-arg="--authentication-keys-directory=/pubkeys" \
    --container-arg="--private-key-location=/keys/ssh_key" \
    --container-arg="--bind-random-ports=false" \
    --container-arg="--bind-random-subdomains=false" \
    --container-arg="--bind-random-aliases=false" \
    --container-arg="--tcp-aliases=true" \
    --container-arg="--service-console=true" \
    --container-arg="--log-to-client=true" \
    --container-arg="--admin-console=true" \
    --container-arg="--verify-ssl=false" \
    --container-arg="--https-ondemand-certificate=false" \
    --container-arg="--https-ondemand-certificate-accept-terms=false" \
    --container-arg="--https-ondemand-certificate-email=certs@YOURDOMAIN" \
    --container-arg="--idle-connection=false" \
    --container-arg="--ping-client-timeout=2m"
```

## Network Setup

### Open the firewall to allow access to all instance ports

```bash
gcloud compute firewall-rules create allow-all-tcp-sish \
    --action="allow" \
    --direction="ingress" \
    --rules="tcp" \
    --source-ranges="0.0.0.0/0" \
    --priority="1000" \
    --target-tags="sish"
```

### Adding a DNS record

Get the external IP address of your machine and create two DNS records

* An `A` record for YOURDOMAIN pointing it to the output below
* An `A` record for *.YOURDOMAIN pointing it to the output below

```bash
gcloud compute instances describe sish \
    --zone="us-central1-a" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

## Using sish

### Try using SSH to connect to the sish service

```bash
ssh -p 2222 -R foo:80:httpbin.org:80 YOURDOMAIN
```

### Access the address sish gave you

```bash
curl -vvv http://foo.YOURDOMAIN/anything
```

## Advanced usage

### Login into your new machine

```bash
gcloud compute ssh sish --zone="us-central1-a"
```

### Adding SSH keys for when you enable auth

```bash
echo "ssh_public_key_here" >> /mnt/stateful_partition/sish/pubkeys/your_user.keys
```

## Tear it down

### First the instance

```bash
gcloud compute instances delete sish \
    --zone="us-central1-a"
```

### Then the firewall rule

```bash
gcloud compute firewall-rules delete allow-all-tcp-sish
```
