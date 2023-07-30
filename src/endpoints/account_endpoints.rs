use rocket::http::Status;
use rocket::response::Redirect;
use rocket::serde::json::{Json, Value};
use rocket::State;

use openidconnect::core::{
    CoreClaimName, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::{
    AccessToken, AuthUrl, AuthorizationCode, EmptyAdditionalProviderMetadata, IssuerUrl,
    JsonWebKeySetUrl, ResponseTypes, Scope, TokenResponse, TokenUrl, UserInfoUrl,
};

use url::Url;
use uuid::Uuid;

use web3_login::authorize::{Authorize, AuthorizeError, Web3Authorize};
use web3_login::claims::{additional_claims, standard_claims, ClaimsMutex};
use web3_login::config::{get_chain_id, get_node, Config};
use web3_login::token::{token, Tokens};

#[get("/<realm>/.well-known/openid-configuration")]
pub fn get_openid_configuration(config: &State<Config>, realm: String) -> Json<Value> {
    let provider_metadata = CoreProviderMetadata::new(
        IssuerUrl::new(format!("{}/account/{}", config.ext_hostname, realm)).unwrap(),
        AuthUrl::new(format!(
            "{}/account/{}/authorize",
            config.ext_hostname, realm
        ))
        .unwrap(),
        JsonWebKeySetUrl::new(format!("{}/account/{}/jwk", config.ext_hostname, realm)).unwrap(),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(format!("{}/account/{}/token", config.ext_hostname, realm)).unwrap(),
    ))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!(
            "{}/account/{}/userinfo",
            config.ext_hostname, realm
        ))
        .unwrap(),
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

    Json(serde_json::to_value(provider_metadata).unwrap())
}

#[get("/.well-known/oauth-authorization-server/<realm>/authorize")]
pub fn get_oauth_authorization_server(config: &State<Config>, realm: String) -> Json<Value> {
    get_openid_configuration(config, realm)
}

#[get(
    "/<realm>/authorize?<client_id>&<redirect_uri>&<state>&<response_type>&<response_mode>&<nonce>&<account>&<signature>&<chain_id>&<contract>"
)]
pub async fn get_authorize(
    config: &State<Config>,
    claims: &State<ClaimsMutex>,
    tokens: &State<Tokens>,
    realm: String,
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
    if account.is_none() {
        let mut url = Url::parse(&format!("{}/", config.frontend_host)).unwrap();
        url.query_pairs_mut()
            .clear()
            .append_pair("client_id", &client_id)
            .append_pair("state", &state.unwrap_or_default())
            .append_pair("nonce", &nonce.unwrap_or_default())
            .append_pair("response_type", &response_type.unwrap_or_default())
            .append_pair("response_mode", &response_mode.unwrap_or_default())
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("realm", &realm.clone())
            .append_pair(
                "chain_id",
                &chain_id.clone().unwrap_or_else(|| realm.clone()),
            )
            .append_pair("contract", &contract.unwrap_or_else(|| client_id.clone()));
        return Ok(Redirect::temporary(url.to_string()));
    };

    let realm_or_chain_id = match realm.as_str() {
        "default" => chain_id.clone().unwrap_or_else(|| "default".into()),
        _ => realm.clone(),
    };

    let node_provider = get_node(config, &realm_or_chain_id);

    let authorize = Web3Authorize {
        account: account.clone(),
        nonce: nonce.clone(),
        signature: signature.clone(),
    };

    match authorize.authorize().await {
        Ok(_) => (),
        Err(err) => match err {
            AuthorizeError::AccountError => {
                return Ok(Redirect::temporary("/400.html?message=account%20missing"))
            }
            AuthorizeError::NonceError => {
                return Ok(Redirect::temporary("/400.html?message=nonce%20missing"))
            }
            AuthorizeError::SignatureError => {
                return Ok(Redirect::temporary("/400.html?message=signature%20missing"))
            }
            AuthorizeError::NFTError => return Ok(Redirect::temporary("/401.html")),
        },
    };

    let redirect_uri = Url::parse(&redirect_uri);

    if redirect_uri.is_err() {
        return Ok(Redirect::temporary(
            "/400.html?message=wrong%20redirect%20uri",
        ));
    }

    let mut redirect_uri = redirect_uri.unwrap();

    let access_token = AccessToken::new(Uuid::new_v4().to_string());
    let code = AuthorizationCode::new(Uuid::new_v4().to_string());
    let chain_id = get_chain_id(config, &realm_or_chain_id);

    let standard_claims = standard_claims(&account.clone().unwrap());

    let node_provider_url = Url::parse(&node_provider).unwrap();
    let node_provider_host = node_provider_url.host().unwrap().to_string();

    let additional_claims = additional_claims(
        &account.unwrap(),
        &nonce.clone().unwrap(),
        &signature.unwrap(),
        &chain_id,
        &node_provider_host,
        "",
    );

    claims
        .standard_claims
        .lock()
        .unwrap()
        .insert(access_token.secret().clone(), standard_claims.clone());
    claims
        .additional_claims
        .lock()
        .unwrap()
        .insert(access_token.secret().clone(), additional_claims.clone());

    let token = token(
        config,
        client_id,
        nonce,
        standard_claims,
        additional_claims,
        access_token.clone(),
        code.clone(),
    )
    .await;

    let id_token = token.id_token().unwrap().to_string();

    tokens
        .bearer
        .lock()
        .unwrap()
        .insert(code.secret().clone(), access_token.secret().clone());
    tokens
        .muted
        .lock()
        .unwrap()
        .insert(access_token.secret().clone(), token);

    if let Some(response_type) = response_type {
        if response_type.contains("code") {
            redirect_uri
                .query_pairs_mut()
                .append_pair("code", code.secret());
        }
        if response_type.contains("id_token") || response_type.contains("token") {
            redirect_uri
                .query_pairs_mut()
                .append_pair("id_token", &id_token);
        }
    } else {
        redirect_uri
            .query_pairs_mut()
            .append_pair("code", code.secret());
    };

    if let Some(state) = state {
        redirect_uri.query_pairs_mut().append_pair("state", &state);
    };

    Ok(Redirect::temporary(redirect_uri.to_string()))
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
    get_authorize(
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
        contract,
    )
    .await
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
        let response = client.get("/account/default/jwk").dispatch();
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

    #[test]
    fn account_valid_signature() {
        let client_id = "foo";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/account/authorize?client_id={}&redirect_uri=https://example.com&nonce={}&account={}&signature={}",
                client_id, nonce, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
    }
}
