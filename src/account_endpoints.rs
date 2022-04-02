use rocket::response::content;
use rocket::serde::json::{Json, Value};
use rocket::State;

use openidconnect::core::{
    CoreClaimName, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, ResponseTypes, Scope,
    TokenUrl, UserInfoUrl,
};
use web3_login::config::Config;
use web3_login::jwk::jwk;

#[get("/jwk")]
pub fn get_jwk(config: &State<Config>) -> Json<Value> {
    Json(jwk(config, "".into()))
}

#[get("/<realm>/.well-known/openid-configuration")]
pub fn get_openid_configuration(config: &State<Config>, realm: String) -> content::Json<Value> {
    let provider_metadata = CoreProviderMetadata::new(
        IssuerUrl::new(format!("{}/{}", config.ext_hostname, realm)).unwrap(),
        AuthUrl::new(format!("{}/{}/authorize", config.ext_hostname, realm)).unwrap(),
        JsonWebKeySetUrl::new(format!("{}/{}/jwk", config.ext_hostname, realm)).unwrap(),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(format!("{}/{}/token", config.ext_hostname, realm)).unwrap(),
    ))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!("{}/{}/userinfo", config.ext_hostname, realm)).unwrap(),
    ))
    .set_scopes_supported(Some(vec![Scope::new("openid".to_string())]))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
        CoreClaimName::new("name".to_string()),
    ]));

    content::Json(serde_json::to_value(&provider_metadata).unwrap())
}

#[get("/.well-known/oauth-authorization-server/<realm>/authorize")]
pub fn get_oauth_authorization_server(
    config: &State<Config>,
    realm: String,
) -> content::Json<Value> {
    get_openid_configuration(config, realm)
}

#[cfg(test)]
mod tests {
    use crate::rocket;
    use rocket::http::Status;
    use rocket::local::blocking::Client;
    use serde_json::Value;

    #[test]
    fn test_jwk() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/account/jwk").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<Value>().unwrap();

        assert!(response.get("keys").is_some());
    }

    #[test]
    fn test_openid_configuration() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client
            .get("/account/default/.well-known/openid-configuration")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<Value>().unwrap();

        assert!(response.get("issuer").is_some());
        assert!(response.get("jwks_uri").is_some());
    }

    #[test]
    fn test_oauth_authorization_server() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client
            .get("/account/.well-known/oauth-authorization-server/default/authorize")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<Value>().unwrap();

        assert!(response.get("issuer").is_some());
        assert!(response.get("jwks_uri").is_some());
    }
}
