use openidconnect::core::CoreJsonWebKeySet;
use openidconnect::PrivateSigningKey;
use serde_json::Value;
use std::error::Error;

use crate::config::Config;
use crate::signing_key_store::SigningKeyStore;
use crate::traits::JWKTrait;

pub struct JWKImpl {
    config: Config,
}

impl JWKImpl {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

impl JWKTrait for JWKImpl {
    fn jwk(&self) -> Result<Value, Box<dyn Error>> {
        jwk(&self.config)
    }
}

pub fn jwk(config: &Config) -> Result<Value, Box<dyn Error>> {
    let mut jwks = Vec::new();

    if let Ok(eddsa_key) = config.get_eddsa_key() {
        jwks.push(eddsa_key.as_verification_key());
    }

    if let Ok(rsa_key) = config.get_rsa_key() {
        jwks.push(rsa_key.as_verification_key());
    }

    let jwks = CoreJsonWebKeySet::new(jwks);

    Ok(serde_json::to_value(jwks)?)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_jwk() {
        let mut config: Config = Config::default();
        config.eddsa_pem = Some(
            r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINsjesLaPcnsC79ywSYvigidJ2TQ+aOBPsOh3KJg5Yk+
-----END PRIVATE KEY-----"#
                .to_string(),
        );
        config.rsa_pem = Some(
            r#"-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDLbbQYA4uc0GeUSYlBrapitZlZPcCMMx+IJ30A18uK5/VIIpuq
1NgfovIq1Kaw3EZ5FeNwxvG8k78gnQLVxe/icSbwWeSVvaAN4JzsNmmNT4RlBAex
F88iUvsNJjC/15xGPgcejwl+6CBwE0kmhV/p7pQVMzMhV8qQqKH46Z46zQIDAQAB
AoGBAILv5rZ6ObfCsJjSyET9Cimk58J4K+JR2Z7ig+QyAfIzoT5AAGBxxXZ/hE4r
N+uorLetbgqeEuSlWKUeSr/cOq0ol4Pw9mjuVz2/36R60/uT9MSfImk4MfXsdgqO
H+QfYw24rVIulDk3WT3pGJ7Oe51pqenanFjrCXdmnj81BJJlAkEA8XhhJBr0YftY
2D0Bli0uNc9TJ4KiZmvY7dcwwgrWSnxS1Gc8z7EVgGHHndcE5pw5QaQwRj0YezzF
JbauO/redwJBANerU9xG3dpufnrH/oQ+ZWA8m1OHVL9Wwo5XYodeYYYKnL7qRiNY
McscyJKiLbbzuzo8IJdBnkXgIK4sbd0RLdsCQDxmWR4X4/MyVNnaALCY4osxLeKf
KZIm/d8YSajv3wRIrstUe4CUEgXH74+Kvj4U67mAoVagZ6RD4ih51oFIUicCQBUb
cXOng+Ly2XIOzLwIl0dZ5yG/pu2rAhOIPd5dwFGsDDcrGn4vDYCBaqffM3YqWHKU
m+Pxyhmwm8IwGvh9y+0CQHMARWF0WNIo9nGZUL9AeLBA+gdGeGZZAIAh1kjoz//o
zBJcklyiwc4iCd5T6Ja8HFzgJDSKCxAoKfHEg/JXS8I=
-----END RSA PRIVATE KEY-----"#
                .to_string(),
        );

        let jwks = jwk(&config);
        assert!(jwks.is_ok());
        let jwks = jwks.unwrap();

        assert_eq!("OKP", jwks["keys"][0]["kty"].as_str().unwrap());
        assert_eq!("Ed25519", jwks["keys"][0]["crv"].as_str().unwrap());
        assert_eq!("OKP", jwks["keys"][0]["kty"].as_str().unwrap());
        assert_eq!("default-eddsa", jwks["keys"][0]["kid"].as_str().unwrap());
        println!("{:?}", jwks["keys"]);
        assert_eq!("RSA", jwks["keys"][1]["kty"].as_str().unwrap());
        assert_eq!("default-eddsa", jwks["keys"][0]["kid"].as_str().unwrap());

        config.eddsa_pem = Some("error pem".to_string());
        let jwks = jwk(&config);
        assert!(jwks.is_ok());
    }
}
