# web3-login

[![Build Status](https://github.com/web3-login/web3-login/actions/workflows/coverage.yml/badge.svg)](https://github.com/web3-login/web3-login/actions)
[![codecov](https://codecov.io/gh/web3-login/web3-login/branch/main/graph/badge.svg?token=0QLPT8IY0F)](https://codecov.io/gh/web3-login/web3-login)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Web3-Login** is a decentralized OpenID Connect (OIDC) provider leveraging web3 technologies. Unlike centralized authentication systems, it offers a seamless authentication experience using your Ethereum address. No personal data or passwords required—just sign the transaction and you're authenticated!

## Why Web3 Login?

The internet today largely relies on identity-based access rather than ownership-based access authorization. Web3-Login bridges this gap. It uses Ethereum addresses as identities and verifies the ownership of NFTs to grant access to services. In essence, it embodies the core principle of web3: decentralization.

### Inspiration

Our inspiration stems from the realization that most online services today hinge on identities instead of actual ownership of access authorization. This paradigm shift, from identity to ownership, inspired us to create Web3-Login. The service uses Ethereum addresses as a form of identity, but it's the ownership of an NFT that grants access to the various online services.

### What does it do?

Web3-Login revolutionizes the traditional login mechanism. Instead of usernames and passwords, it uses web3 keys (public/private key pairs) and NFTs. Developers can thus integrate a novel login functionality into their projects, allowing users to use their crypto wallets for authentication.

To get started, all you need is a Web3 wallet such as MetaMask or Coinbase. No separate username or password. Just choose your Web3 wallet from the list, and sign your transactions.

## Quickstart

To get started with web3-login, you can follow these steps to build and run the application:

```sh
cargo build   # Build the project
cargo test    # Run tests
cargo run     # Start the web3-login service
```

## Configuration

### Generate Keys

```sh
openssl genpkey -algorithm ed25519
openssl genrsa --traditional -out private_rsa.pem 1024
```

Copy the generated private key to config.yml.

## Using Cloudflare Argo Tunnel with Docker

Cloudflare Argo Tunnel provides a secure way to connect your infrastructure to the Cloudflare network without exposing public IPs. By integrating it with the `web3-login` service, you can achieve improved performance and security for user authentication. It's especially beneficial for projects where identity and privacy matter.

### Setting up Cloudflare Argo Tunnel

1. Create a new tunnel for your service:
   ```sh
   cloudflared tunnel create oidc-web3-login
   ```

2. Move the generated JSON (your tunnel credentials) to the `.cloudflared` directory:
   ```sh
   cp changeme-e246.json .cloudflared/
   ```

3. Update the tunnel settings in your `.cloudflared/config.yml`:
   ```yml
   url: http://provider:8080
   tunnel: changeme-e246
   credentials-file: /etc/cloudflared/changeme-e246.json
   ```

### Running with Docker

With the configurations in place, you can now run the `web3-login` service along with Cloudflare Argo Tunnel using Docker Compose:

```sh
docker-compose up -d
```

### Optional: Running web3-login in Docker without Docker Compose

If you wish to run the `web3-login` service without Docker Compose, you can use the following `docker run` command:

```sh
docker run -d -p 8080:8080 --name web3-login ghcr.io/web3-login/web3-login/web3-login:latest
```

**Note**: Ensure the configurations and required volumes are appropriately set if you're opting for this method.

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
## Frequently Asked Questions (FAQs)

### What if the Web3-Login domain is not renewed or there are issues with hosting? Can I host `oidc.web3-login.net` on my own server?

#### Answer:

Absolutely! The resilience and decentralization principle behind Web3-Login means you're not locked into relying solely on our infrastructure.

Web3-Login is constructed atop the OpenID Connect (OIDC) framework. This enables anyone to host the OIDC server on their own infrastructure. So, even if there were issues with our primary domain, you can seamlessly transition by setting up the OIDC server on a different domain and pointing your application there.

To achieve this, you would:
1. Host the OIDC server on your chosen domain or server.
2. Update your OpenID Connect client's configuration to refer to your new domain.

It's all about giving you the control. The decentralization aspect ensures that the login process remains robust and reliable, irrespective of potential disruptions to our primary service. 

For a practical example, when setting up on your own domain, you'll need to replace the Authorize URI in the [example config](https://web3-login.net/#/config) with your server's domain.
