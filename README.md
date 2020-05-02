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

How it works
------------

SSH can normally forward local and remote ports. This service implements
an SSH server that only does that and nothing else. The service supports
multiplexing connections over HTTP/HTTPS with WebSocket support. Just assign a
remote port as port `80` to proxy HTTP traffic and `443` to proxy HTTPS traffic.
If you use any other remote port, the server will listen to the port for connections,
but only if that port is available.

You can choose your own subdomain instead of relying on a randomly assigned one
by setting the `-sish.forcerandomsubdomain` option to `false` and then selecting a
subdomain by prepending it to the remote port specifier:

`ssh -p 2222 -R foo:80:localhost:8080 ssi.sh`

If the selected subdomain is not taken, it will be assigned to your connection.

Authentication
--------------

If you want to use this service privately, it supports both public key and password
authentication. To enable authentication, set `-sish.auth=true` as one of your CLI
options and be sure to configure `-sish.password` or `-sish.keysdir` to your liking.
The directory provided by `-sish.keysdir` is watched for changes and will reload the
authorized keys automatically. The authorized cert index is regenerated on directory
modification, so removed public keys will also automatically be removed. Files in this
directory can either be single key per file, or multiple keys per file separated by newlines,
similar to `authorized_keys`. Password auth can be disabled by setting `-sish.password=""` as a CLI option.

One of my favorite ways of using this for authentication is like so:

```bash
sish@sish0:~/sish/pubkeys# curl https://github.com/antoniomika.keys > antoniomika
```

This will load my public keys from GitHub, place them in the directory that sish is watching,
and then load the pubkey. As soon as this command is run, I can SSH normally and it will authorize me.

Whitelisting IPs
----------------

Whitelisting IP ranges or countries is also possible. Whole CIDR ranges can be
specified with the `-sish.whitelistedips` option that accepts a comma-separated
string like "192.30.252.0/22,185.199.108.0/22". If you want to whitelist a single
IP, use the `/32` range.

To whitelist countries, use `sish.whitelistedcountries` with a comma-separated
string of countries in ISO format (for example, "pt" for Portugal). You'll also
need to set `-sish.usegeodb` to `true`.

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

```
