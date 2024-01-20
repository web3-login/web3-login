use openidconnect::core::{CoreEdDsaPrivateSigningKey, CoreJsonWebKeySet};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use serde_json::Value;
use std::error::Error;

use crate::config::Config;
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
    let jwks = CoreJsonWebKeySet::new(vec![CoreEdDsaPrivateSigningKey::from_ed25519_pem(
        config.eddsa_pem.as_ref().unwrap(),
        Some(JsonWebKeyId::new(config.key_id.to_string())),
    )?
    .as_verification_key()]);

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
        let jwks = jwk(&config);
        assert!(jwks.is_ok());

        config.eddsa_pem = Some("error pem".to_string());
        let jwks = jwk(&config);
        assert!(jwks.is_err());
    }
}
