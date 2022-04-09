use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey, CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, AuthorizationCode, EmptyExtraTokenFields, IdToken, IdTokenClaims,
    IdTokenFields, IssuerUrl, JsonWebKeyId, StandardClaims, StandardTokenResponse,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::claims::Claims;
use crate::config::Config;

pub type Web3IdTokenFields = IdTokenFields<
    Claims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

pub type Web3TokenResponse = StandardTokenResponse<Web3IdTokenFields, CoreTokenType>;

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
    let rsa_pem = config.rsa_pem.clone();
    let id_token = IdToken::new(
        IdTokenClaims::new(
            IssuerUrl::new(config.ext_hostname.to_string()).unwrap(),
            vec![Audience::new(client_id)],
            Utc::now() + Duration::seconds(300),
            Utc::now(),
            standard_claims,
            additional_claims,
        ),
        // The private key used for signing the ID token. For confidential clients (those able
        // to maintain a client secret), a CoreHmacKey can also be used, in conjunction
        // with one of the CoreJwsSigningAlgorithm::HmacSha* signing algorithms. When using an
        // HMAC-based signing algorithm, the UTF-8 representation of the client secret should
        // be used as the HMAC key.
        &CoreRsaPrivateSigningKey::from_pem(
            &rsa_pem.unwrap_or_default(),
            Some(JsonWebKeyId::new(config.key_id.to_string())),
        )
        .expect("Invalid RSA private key"),
        // Uses the RS256 signature algorithm. This crate supports any RS*, PS*, or HS*
        // signature algorithm.
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        // When returning the ID token alongside an access token (e.g., in the Authorization Code
        // flow), it is recommended to pass the access token here to set the `at_hash` claim
        // automatically.
        Some(&access_token),
        // When returning the ID token alongside an authorization code (e.g., in the implicit
        // flow), it is recommended to pass the authorization code here to set the `c_hash` claim
        // automatically.
        Some(&code),
    )
    .unwrap();

    Web3TokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        Web3IdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    )
}
