use rocket::State;

use openidconnect::core::{CoreJsonWebKeySet, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use serde_json::Value;

use crate::config::Config;

pub fn jwk(config: &State<Config>, _realm: String) -> Value {
    let jwks = CoreJsonWebKeySet::new(vec![CoreRsaPrivateSigningKey::from_pem(
        config.rsa_pem.as_ref().unwrap(),
        Some(JsonWebKeyId::new(config.key_id.to_string())),
    )
    .expect("Invalid RSA private key")
    .as_verification_key()]);

    serde_json::to_value(&jwks).unwrap()
}
