# sish

An open source serveo/ngrok alternative.

[Read the docs.](https://docs.ssi.sh)

## dev

Clone the `sish` repo:

```bash
git clone git@github.com:antoniomika/sish.git
cd sish
```

Add your SSH public key:

```bash
cp ~/.ssh/id_ed25519.pub ./deploy/pubkeys
```

Run the binary:

```bash
go run main.go --http-address localhost:3000 --domain testing.ssi.sh
```

We have an alias `make dev` for running the binary.

SSH to your host to communicate with sish:

```bash
ssh -p 2222 -R 80:localhost:8080 testing.ssi.sh
```
> The `testing.ssi.sh` DNS record points to `localhost` so anyone can use it for
> development
