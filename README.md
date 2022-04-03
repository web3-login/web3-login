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
