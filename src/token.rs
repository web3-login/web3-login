use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, AuthorizationCode, EmptyExtraTokenFields, IdToken, IdTokenClaims,
    IdTokenFields, IssuerUrl, StandardClaims, StandardTokenResponse,
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

pub fn token(
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

#[cfg(test)]
mod tests {
    use base64::{
        alphabet,
        engine::{self, general_purpose},
        Engine as _,
    };
    use openidconnect::{JsonWebKey, PrivateSigningKey, SubjectIdentifier};
    use serde_json::Value;

    use crate::config::tests::test_config;

    use super::*;

    #[test]
    fn test_jwt_signature() {
        let mut config = test_config();

        config.key_id = "kid".to_string();
        config.eddsa_pem = None;

        let client_id = "client_id".to_string();
        let nonce = Some("nonce".to_string());
        let standard_claims = StandardClaims::new(SubjectIdentifier::new("account".to_string()));
        let additional_claims = Claims {
            account: "account".to_string(),
            nonce: "nonce".to_string(),
            signature: "signature".to_string(),
            chain_id: 1,
            node: "node".to_string(),
            contract: "contract".to_string(),
        };

        let access_token = AccessToken::new("access_token".to_string());
        let code = AuthorizationCode::new("code".to_string());

        let response = token(
            &config,
            client_id,
            nonce,
            standard_claims,
            additional_claims,
            access_token,
            code,
        );

        println!(" response {:?}", response);

        let serialized = serde_json::to_string(&response).unwrap();

        let deserialized: Value = serde_json::from_str(&serialized).unwrap();

        let id_token = deserialized["id_token"].as_str().unwrap();

        assert_eq!(id_token.split(".").count(), 3);

        let header = id_token.split(".").collect::<Vec<&str>>()[0];
        let payload = id_token.split(".").collect::<Vec<&str>>()[1];

        let message = format!("{}.{}", header, payload);

        let decoded_header =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
                .decode(header)
                .unwrap();

        let header: Value = serde_json::from_slice(&decoded_header).unwrap();

        let kid = format!("{}-rsa", config.key_id.to_string());

        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], kid);

        let signature = id_token.split(".").collect::<Vec<&str>>()[2];

        let rsa_key = config.get_rsa_key().unwrap();

        let jwk = rsa_key.as_verification_key();

        let signature = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
            .decode(signature)
            .unwrap();

        let verified = jwk.verify_signature(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            message.as_bytes(),
            &signature,
        );

        if verified.is_err() {
            println!("{:?}", verified);
        }

        assert!(verified.is_ok());
    }
}
