# Getting started

The default stack contains only Geth, EthBFT, and CometBFT. Install Docker with
Compose and OpenSSL, then run:

```bash
git clone https://github.com/smallyunet/ethbft.git
cd ethbft
make deploy
curl http://localhost:8081/ready
```

Send transactions to `http://localhost:8545`. CometBFT transaction broadcast
is disabled because its mempool is configured as `nop`.

Monitoring is optional:

```bash
docker compose --profile observability up -d
```

For Rust development, install Rust 1.91+ and run `make check`. The
single-validator Docker path is `make test-e2e`; the four-validator failure and
catch-up path is `make test-multinode-e2e`.

Protocol v2 cannot reuse v0.2 chain state. Follow the destructive local-only
migration command in the repository README only for a disposable network.
