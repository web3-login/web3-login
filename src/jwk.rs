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

    use crate::config::tests::test_config;

    use super::*;

    #[test]
    fn test_jwk() {
        let mut config = test_config();

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
