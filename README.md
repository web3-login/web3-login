# web3-login

[![Build Status](https://github.com/web3-login/web3-login/actions/workflows/coverage.yml/badge.svg)](https://github.com/web3-login/web3-login/actions)
[![codecov](https://codecov.io/gh/web3-login/web3-login/branch/main/graph/badge.svg?token=0QLPT8IY0F)](https://codecov.io/gh/web3-login/web3-login)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

oidc provider using web3 technologies

## quickstart

```sh
cargo build
cargo test
cargo run
```

## cloudflare argo tunnel and docker

```sh
cloudflared tunnel create oidc-web3-login
cp changeme-e246.json .cloudflared/
```

Update tunnel and credentials-file in `.cloudflared/config.yml`.

```yml
url: http://provider:8080
tunnel: changeme-e246
credentials-file: /etc/cloudflared/changeme-e246.json
```

Now you can run `docker-compose up -d`.

## Claims

| Claim          | Example                                                                                                                                |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| sub            | '0x8f4f7365981a73dd61d5aa74cce4c0f251f67fac'                                                                                           |
| name           | 'anonymous'                                                                                                                            |
| email          | 'no-reply@example.com'                                                                                                                 |
| email_verified | false                                                                                                                                  |
| account        | '0x8f4f7365981a73dd61d5aa74cce4c0f251f67fac'                                                                                           |
| signature      | '0xb37a8dc999eb2dffbd4479e23d3efff079414a6ddb5f97a19d39471afc83c7007951266c4ea734bb43a217b751c3f78913ed011cb27a847ecc72e753194f30131c' |
| chain_id       | 256                                                                                                                                    |
| node           | 'https://http-testnet.hecochain.com'                                                                                                   |
| contract       | '0xa0d4E5CdD89330ef9d0d1071247909882f0562eA'

## List of supported chains

| Chain                          | Authorize URI           | Contract to use as Client ID               | Marketplace to get NFT                                     | Faucet                                                                                        |     |
| ------------------------------ | ----------------------- | ------------------------------------------ | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------- | --- |
| Kovan (42)                     | / or /default/authorize | 0x3B8270447b913d0b935e09d1C2daEc3F5CDD968f | https://devpavan04.github.io/cryptoboys-nft-marketplace/   | https://ethdrop.dev/                                                                          |     |
| OKExChain (65)                 | /okt/authorize          | 0xf0263c1D56A167cDCF72086071f96CbB8a077AE9 | https://nft-login.github.io/nft-login-marketplace/okt/     | https://okexchain-docs.readthedocs.io/en/latest/developers/quick-start.html#get-testnet-token |     |
| Clover (1023)                  | /clv/authorize          |                                            |                                                            | https://faucet.clovernode.com/                                                                |     |
| HECO Testnet (256)             | /heco/authorize         | 0xa0d4E5CdD89330ef9d0d1071247909882f0562eA | https://nft-login.github.io/nft-login-marketplace/heco/    | https://scan-testnet.hecochain.com/faucet                                                     |     |
| Celo alfajores (44787)         | /celo/authorize         | 0xBa4e569A5156C00348B89653968c2C294f80E151 | https://nft-login.github.io/nft-login-marketplace/celo/    | https://celo.org/developers/faucet                                                            |     |
| Polygon mumbai (80001)         | /polygon/authorize      | 0x8866afd737201d9Fcc16438b65f1E3db7A3A5Ddb | https://nft-login.github.io/nft-login-marketplace/polygon/ | https://faucet.polygon.technology/                                                            |     |
| Metis stardust (588)           | /metis/authorize        | 0x8866afd737201d9Fcc16438b65f1E3db7A3A5Ddb | https://nft-login.github.io/nft-login-marketplace/metis/   | https://rinkeby-faucet.metis.io/                                                              |     |
| Meter Testnet (83)             | /meter/authorize        | 0x14e1a78dE8763D6Ccaf37E7318415E19D8EE4975 | https://market.nft-login.net/                              | http://faucet-warringstakes.meter.io/                                                         |     |
| Theta Testnet (365)            | /theta/authorize        | 0x8fb36197889f23E76e68E3FD57c6063A21DdE897 | https://market.nft-login.net/                              |                                                                                               |     |
| Avalanche FUJI C-Chain (43113) | /avax/authorize         | 0x51320F31d30c56c8107D82b4C67C5EdDfCa88bc2 | https://market.nft-login.net/                              | https://faucet.avax-test.network/                                                             |     |
| Binance Smart Chain (97)       | /binance/authorize      | 0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4 | https://market.nft-login.net/                              | https://testnet.binance.org/faucet-smart                                                      |     |
| Evmos Testnet (9000)           | /evmos/authorize        | 0xf141C38096539185efbca485Eb858Bd274a6651c | https://market.nft-login.net/                              | https://faucet.evmos.org/                                                                     |     |
|                                |                         |                                            |                                                            |                                                                                               |     |
|                                |                         |                                            |                                                            |                                                                                               |     |
