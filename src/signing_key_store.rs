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

    use super::*;

    #[test]
    fn test_load_config_yml() {
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
}
