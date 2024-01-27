use std::{error::Error, path::PathBuf};

use openidconnect::{
    core::{CoreEdDsaPrivateSigningKey, CoreRsaPrivateSigningKey},
    JsonWebKeyId,
};

use crate::config::Config;

pub trait SigningKeyStore {
    fn get_rsa_key(&self) -> Result<CoreRsaPrivateSigningKey, Box<dyn Error>>;
    fn get_eddsa_key(&self) -> Result<CoreEdDsaPrivateSigningKey, Box<dyn Error>>;
}

impl SigningKeyStore for Config {
    fn get_rsa_key(&self) -> Result<CoreRsaPrivateSigningKey, Box<dyn Error>> {
        match (&self.rsa_pem, &self.rsa_pem_file) {
            (Some(rsa_pem), _) => {
                let jwk = CoreRsaPrivateSigningKey::from_pem(
                    rsa_pem.as_ref(),
                    Some(JsonWebKeyId::new(format!(
                        "{}-{}",
                        self.key_id.to_string(),
                        "rsa"
                    ))),
                )?;
                Ok(jwk)
            }
            (_, Some(rsa_pem_file)) => {
                let rsa_pem = std::fs::read_to_string::<&PathBuf>(rsa_pem_file)?;
                let jwk = CoreRsaPrivateSigningKey::from_pem(
                    rsa_pem.as_ref(),
                    Some(JsonWebKeyId::new(format!(
                        "{}-{}",
                        self.key_id.to_string(),
                        "rsa"
                    ))),
                )?;
                Ok(jwk)
            }
            _ => Err("No rsa_pem".into()),
        }
    }

    fn get_eddsa_key(&self) -> Result<CoreEdDsaPrivateSigningKey, Box<dyn Error>> {
        match &self.eddsa_pem {
            Some(eddsa_pem) => {
                let jwk = CoreEdDsaPrivateSigningKey::from_ed25519_pem(
                    eddsa_pem.as_ref(),
                    Some(JsonWebKeyId::new(format!(
                        "{}-{}",
                        self.key_id.to_string(),
                        "eddsa"
                    ))),
                )?;
                Ok(jwk)
            }
            None => Err("No eddsa_pem".into()),
        }
    }
}

#[cfg(test)]
mod tests {

    use openidconnect::{JsonWebKey, PrivateSigningKey};

    use crate::config::tests::test_config;

    use super::*;

    #[test]
    fn test_load_config_yml() {
        let config = test_config();

        let rsa_key = config.get_rsa_key().unwrap();

        assert_eq!(
            rsa_key.as_verification_key().key_id().unwrap().to_string(),
            "default-rsa"
        );

        let eddsa_key = config.get_eddsa_key().unwrap();

        assert_eq!(
            eddsa_key
                .as_verification_key()
                .key_id()
                .unwrap()
                .to_string(),
            "default-eddsa"
        );
    }

    #[test]
    fn test_sign() {
        let config = test_config();

        let rsa_key = config.get_rsa_key().unwrap();

        let message = "nonce".to_string();
        let signature = rsa_key
            .sign(
                &openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                &message.as_bytes(),
            )
            .unwrap();

        assert_eq!(signature.len(), 128);
    }
}
