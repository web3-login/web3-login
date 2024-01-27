use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreEdDsaPrivateSigningKey, CoreGenderClaim, CoreJsonWebKeyType,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, AuthorizationCode, EmptyExtraTokenFields, IdToken, IdTokenClaims,
    IdTokenFields, IssuerUrl, JsonWebKeyId, PrivateSigningKey, StandardClaims,
    StandardTokenResponse,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::claims::Claims;
use crate::config::Config;
use crate::signing_key_store::SigningKeyStore;
use crate::traits::TokenTrait;

pub type Web3IdTokenFields = IdTokenFields<
    Claims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

pub type Web3TokenResponse = StandardTokenResponse<Web3IdTokenFields, CoreTokenType>;

#[derive(Clone)]
pub struct Tokens {
    pub muted: Arc<Mutex<HashMap<String, Web3TokenResponse>>>,
    pub bearer: Arc<Mutex<HashMap<String, String>>>,
}

pub async fn token(
    config: &Config,
    client_id: String,
    _nonce: Option<String>,
    standard_claims: StandardClaims<CoreGenderClaim>,
    additional_claims: Claims,
    access_token: AccessToken,
    code: AuthorizationCode,
) -> Web3TokenResponse {
    let claims = IdTokenClaims::new(
        IssuerUrl::new(config.ext_hostname.to_string()).unwrap(),
        vec![Audience::new(client_id)],
        Utc::now() + Duration::seconds(300),
        Utc::now(),
        standard_claims,
        additional_claims,
    );

    let id_token = match (config.get_eddsa_key(), config.get_rsa_key()) {
        (Ok(eddsa_key), _) => IdToken::new(
            claims,
            &eddsa_key,
            CoreJwsSigningAlgorithm::EdDsaEd25519,
            Some(&access_token),
            Some(&code),
        )
        .unwrap(),
        (_, Ok(rsa_key)) => IdToken::new(
            claims,
            &rsa_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&access_token),
            Some(&code),
        )
        .unwrap(),
        _ => panic!("No key"),
    };
    Web3TokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        Web3IdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    )
}

pub struct TokenImpl {
    tokens: Tokens,
}

impl TokenImpl {
    pub fn new(tokens: Tokens) -> Self {
        Self { tokens }
    }
}

impl TokenTrait for TokenImpl {
    fn get_token(&self, code: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mutex = self.tokens.bearer.lock().unwrap();
        let access_token = mutex.get(&code);
        if access_token.is_none() {
            return Err("Invalid Code".into());
        }
        let access_token = access_token.unwrap();
        let mutex = self.tokens.muted.lock().unwrap();
        let token = mutex.get(access_token);
        match token {
            Some(token) => Ok(serde_json::to_value(token.clone())?),
            _ => Err("Invalid Code".into()),
        }
    }
}
