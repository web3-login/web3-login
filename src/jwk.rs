use openidconnect::core::{CoreJsonWebKeySet, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use serde_json::Value;
use std::error::Error;

use crate::config::Config;

pub fn jwk(config: &Config) -> Result<Value, Box<dyn Error>> {
    let jwks = CoreJsonWebKeySet::new(vec![CoreRsaPrivateSigningKey::from_pem(
        config.rsa_pem.as_ref().unwrap(),
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
        config.rsa_pem = Some(include_str!("../do-not-use.pem").to_string());
        let jwks = jwk(&config);
        assert!(jwks.is_ok());

        config.rsa_pem = Some("error pem".to_string());
        let jwks = jwk(&config);
        assert!(jwks.is_err());
    }
}
