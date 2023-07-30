use openidconnect::core::{
    CoreClaimName, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::{core::CoreGenderClaim, UserInfoClaims};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, ResponseTypes, Scope,
    TokenUrl, UserInfoUrl,
};
use rocket::form::Form;
use rocket::http::Status;
use rocket::response::status::NotFound;
use rocket::response::Redirect;
use rocket::serde::json::{Json, Value};
use rocket::State;
use web3_login::claims::{Claims, ClaimsMutex};
use web3_login::config::Config;
use web3_login::jwk::jwk;
use web3_login::token::{Tokens, Web3TokenResponse};
use web3_login::userinfo::userinfo;

use crate::bearer::Bearer;

pub mod account_endpoints;
pub mod nft_endpoints;

#[derive(FromForm)]
pub struct PostData {
    pub grant_type: Option<String>,
    pub code: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
}

#[get("/<_realm>/jwk")]
pub fn get_jwk(config: &State<Config>, _realm: String) -> Json<Value> {
    get_default_jwk(config)
}

#[get("/jwk")]
pub fn get_default_jwk(config: &State<Config>) -> Json<Value> {
    Json(jwk(config).unwrap())
}

#[get("/.well-known/openid-configuration")]
pub fn get_openid_configuration(config: &State<Config>) -> Json<Value> {
    let provider_metadata = CoreProviderMetadata::new(
        IssuerUrl::new(config.ext_hostname.to_string()).unwrap(),
        AuthUrl::new(format!("{}/authorize", config.ext_hostname)).unwrap(),
        JsonWebKeySetUrl::new(format!("{}/jwk", config.ext_hostname)).unwrap(),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(format!("{}/token", config.ext_hostname)).unwrap(),
    ))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!("{}/userinfo", config.ext_hostname)).unwrap(),
    ))
    .set_scopes_supported(Some(vec![
        Scope::new("openid".to_string()),
        Scope::new("nft".to_string()),
    ]))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
        CoreClaimName::new("name".to_string()),
    ]));

    Json(serde_json::to_value(provider_metadata).unwrap())
}

#[get("/.well-known/oauth-authorization-server/authorize")]
pub fn get_oauth_authorization_server(config: &State<Config>) -> Json<Value> {
    get_openid_configuration(config)
}

#[allow(unused_variables)]
#[get("/<realm>/userinfo")]
pub async fn get_userinfo(
    claims: &State<ClaimsMutex>,
    bearer: Bearer,
    realm: String,
) -> Result<Json<UserInfoClaims<Claims, CoreGenderClaim>>, NotFound<String>> {
    let access_token = bearer.0;
    match userinfo(claims, access_token) {
        Some(userinfo) => Ok(Json(userinfo)),
        None => Err(NotFound("No user found!".to_string())),
    }
}

#[get("/userinfo")]
pub async fn get_default_userinfo(
    claims: &State<ClaimsMutex>,
    bearer: Bearer,
) -> Result<Json<UserInfoClaims<Claims, CoreGenderClaim>>, NotFound<String>> {
    get_userinfo(claims, bearer, "default".into()).await
}

#[options("/userinfo")]
pub async fn options_default_userinfo() {}

#[options("/<_realm>/userinfo")]
pub async fn options_userinfo(_realm: String) {}

#[get("/<_realm>/token?<code>")]
pub fn get_token(
    tokens: &State<Tokens>,
    _realm: String,
    code: String,
) -> Result<Json<Web3TokenResponse>, NotFound<String>> {
    let mutex = tokens.bearer.lock().unwrap();
    let access_token = mutex.get(&code);
    if access_token.is_none() {
        return Err(NotFound("Invalid Code".to_string()));
    }
    let access_token = access_token.unwrap();
    let mutex = tokens.muted.lock().unwrap();
    let token = mutex.get(access_token);
    match token {
        Some(token) => Ok(Json(token.clone())),
        _ => Err(NotFound("Invalid Code".to_string())),
    }
}

#[get("/token?<code>")]
pub fn get_default_token(
    tokens: &State<Tokens>,
    code: String,
) -> Result<Json<Web3TokenResponse>, NotFound<String>> {
    get_token(tokens, "default".into(), code)
}

#[post("/token", data = "<post_data>")]
pub async fn post_default_token_endpoint(
    tokens: &State<Tokens>,
    post_data: Form<PostData>,
) -> Result<Json<Web3TokenResponse>, NotFound<String>> {
    get_default_token(tokens, post_data.code.clone())
}

#[get(
    "/authorize?<client_id>&<redirect_uri>&<state>&<response_type>&<response_mode>&<nonce>&<account>&<signature>&<realm>&<chain_id>&<contract>"
)]
pub async fn get_default_authorize(
    config: &State<Config>,
    claims: &State<ClaimsMutex>,
    tokens: &State<Tokens>,
    realm: Option<String>,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    response_type: Option<String>,
    response_mode: Option<String>,
    nonce: Option<String>,
    account: Option<String>,
    signature: Option<String>,
    chain_id: Option<String>,
    contract: Option<String>,
) -> Result<Redirect, (Status, String)> {
    match contract {
        Some(contract) => {
            nft_endpoints::get_authorize(
                config,
                claims,
                tokens,
                realm.unwrap_or_else(|| "default".into()),
                client_id,
                redirect_uri,
                state,
                response_type,
                response_mode,
                nonce,
                account,
                signature,
                chain_id,
                Some(contract),
            )
            .await
        }
        _ => {
            account_endpoints::get_authorize(
                config,
                claims,
                tokens,
                realm.unwrap_or_else(|| "default".into()),
                client_id,
                redirect_uri,
                state,
                response_type,
                response_mode,
                nonce,
                account,
                signature,
                chain_id,
                None,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rocket;
    use rocket::http::{Header, Status};
    use rocket::local::blocking::Client;
    use serde_json::Value;
    use std::collections::HashMap;
    use url::Url;

    #[test]
    fn test_no_userinfo() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client.get("/nft/default/userinfo").dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);

        let response = client
            .get("/nft/default/userinfo")
            .header(Header::new(
                "Authorization",
                format!("Bearer {}", "wrong_bearer_token"),
            ))
            .dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    #[test]
    fn test_openid_configuration() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/.well-known/openid-configuration").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<Value>().unwrap();

        assert!(response.get("issuer").is_some());
        assert!(response.get("jwks_uri").is_some());
    }

    #[test]
    fn test_redirect_no_nft() {
        let client_id = "foo";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&account={}&signature={}",
                client_id, nonce, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        assert!(response
            .headers()
            .get("Location")
            .next()
            .unwrap()
            .starts_with("https://example.com/?code="));
    }

    #[test]
    fn test_redirect_nft() {
        let client_id = "foo";
        let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&contract={}&account={}&signature={}",
                client_id, nonce, contract, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        let response_url = Url::parse(response.headers().get("Location").next().unwrap()).unwrap();

        let params: HashMap<String, String> = response_url
            .query()
            .map(|v| {
                url::form_urlencoded::parse(v.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_else(HashMap::new);

        assert!(params.get("code").is_some());
        let code = params.get("code").unwrap();
        let response = client.get(format!("/token?code={}", code)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = client
            .get(format!("/nft/okt/token?code={}", code))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let token = response.into_json::<Value>().unwrap();
        let access_token = token.get("access_token");
        assert!(access_token.is_some());
        let access_token = access_token.unwrap().as_str().unwrap().to_string();

        let response = client
            .get(format!("/token?code={}", "invalid".to_string()))
            .dispatch();
        assert_eq!(response.status(), Status::NotFound);

        let response = client.get("/userinfo").dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        assert_eq!(response.headers().get("Location").next(), Some("/400.html"));

        let response = client
            .get("/userinfo")
            .header(Header::new(
                "Authorization",
                format!("Bearer {}", access_token),
            ))
            .dispatch();
        assert_ne!(response.status(), Status::BadRequest);
        let userinfo = response.into_json::<Value>().unwrap();

        assert_eq!(userinfo.get("account").unwrap().as_str().unwrap(), account);
        assert_eq!(
            userinfo.get("contract").unwrap().as_str().unwrap(),
            contract
        );
        assert_eq!(userinfo.get("nonce").unwrap().as_str().unwrap(), nonce);
    }
}
