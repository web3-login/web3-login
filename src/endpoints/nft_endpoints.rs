use rocket::http::Status;
use rocket::response::{content, Redirect};
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

use web3_login::claims::{additional_claims, standard_claims, ClaimsMutex};
use web3_login::config::{get_chain_id, get_node, Config};
use web3_login::jwk::jwk;
use web3_login::token::{token, Tokens};
use web3_login::web3::{is_nft_owner_of, validate_signature};

#[get("/<realm>/jwk")]
pub fn get_jwk(config: &State<Config>, realm: String) -> Json<Value> {
    Json(jwk(config, realm))
}

#[get("/<realm>/.well-known/openid-configuration")]
pub fn get_openid_configuration(config: &State<Config>, realm: String) -> content::Json<Value> {
    let provider_metadata = CoreProviderMetadata::new(
        IssuerUrl::new(format!("{}/nft/{}", config.ext_hostname, realm)).unwrap(),
        AuthUrl::new(format!("{}/nft/{}/authorize", config.ext_hostname, realm)).unwrap(),
        JsonWebKeySetUrl::new(format!("{}/nft/{}/jwk", config.ext_hostname, realm)).unwrap(),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(format!("{}/nft/{}/token", config.ext_hostname, realm)).unwrap(),
    ))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!("{}/nft/{}/userinfo", config.ext_hostname, realm)).unwrap(),
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

#[get(
    "/<realm>/authorize?<client_id>&<redirect_uri>&<state>&<response_type>&<response_mode>&<nonce>&<account>&<signature>&<chain_id>&<contract>"
)]
pub async fn authorize_endpoint(
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
        let mut url = Url::parse(&format!("{}/{}", config.ext_hostname, realm)).unwrap();
        url.query_pairs_mut()
            .clear()
            .append_pair("client_id", &client_id)
            .append_pair("state", &state.unwrap_or_default())
            .append_pair("nonce", &nonce.unwrap_or_default())
            .append_pair("response_type", &response_type.unwrap_or_default())
            .append_pair("response_mode", &response_mode.unwrap_or_default())
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("realm", &realm.clone())
            .append_pair("chain_id", &chain_id.clone().unwrap_or(realm.clone()))
            .append_pair("contract", &contract.unwrap_or(client_id.clone()));
        return Ok(Redirect::temporary(url.to_string()));
    };

    if nonce.is_none() {
        return Err((Status::BadRequest, "nonce missing".to_string()));
    }

    if signature.is_none() {
        return Err((Status::BadRequest, "signature missing".to_string()));
    }

    let redirect_uri = Url::parse(&redirect_uri);

    if redirect_uri.is_err() {
        return Err((Status::BadRequest, "wrong redirect uri".to_string()));
    }

    let mut redirect_uri = redirect_uri.unwrap();

    if !validate_signature(
        account.clone().unwrap(),
        nonce.clone().unwrap(),
        signature.clone().unwrap(),
    ) {
        return Err((Status::BadRequest, "no valide signature".to_string()));
    }

    let realm_or_chain_id = match realm.as_str() {
        "default" => chain_id.clone().unwrap_or("default".into()),
        _ => realm.clone(),
    };

    let node_provider = get_node(config, &realm_or_chain_id);
    let contract = contract.unwrap_or(client_id.clone());

    let is_owner = is_nft_owner_of(
        contract.clone(),
        account.clone().unwrap_or_default(),
        node_provider.clone(),
    )
    .await;

    if is_owner.is_ok() {
        if !is_owner.unwrap() {
            return Err((Status::Unauthorized, "account is no owner".to_string()));
        }
    } else {
        return Err((Status::Unauthorized, "account is no owner".to_string()));
    }

    let access_token = AccessToken::new(Uuid::new_v4().to_string());
    let code = AuthorizationCode::new(Uuid::new_v4().to_string());
    let chain_id = get_chain_id(config, &realm_or_chain_id);

    let standard_claims = standard_claims(&account.clone().unwrap());

    let additional_claims = additional_claims(
        &account.unwrap(),
        &nonce.clone().unwrap(),
        &signature.unwrap(),
        &chain_id,
        &node_provider.clone(),
        &contract,
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
        realm,
        client_id,
        nonce,
        standard_claims,
        additional_claims,
        access_token.clone(),
        code.clone(),
    )
    .await;

    println!("{:?}", access_token.secret());
    println!("{:?}", code.secret());
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
        if response_type.contains("id_token") {
            redirect_uri
                .query_pairs_mut()
                .append_pair("id_token", &id_token);
        } else if response_type.contains("token") {
            redirect_uri
                .query_pairs_mut()
                .append_pair("id_token", &id_token);
        }
    } else {
        redirect_uri
            .query_pairs_mut()
            .append_pair("code", code.secret());
    };

    match state {
        Some(state) => {
            redirect_uri.query_pairs_mut().append_pair("state", &state);
        }
        _ => {}
    }

    Ok(Redirect::temporary(redirect_uri.to_string()))
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
        let response = client.get("/nft/default/jwk").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<Value>().unwrap();

        assert!(response.get("keys").is_some());
    }

    #[test]
    fn test_openid_configuration() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client
            .get("/nft/default/.well-known/openid-configuration")
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
            .get("/nft/.well-known/oauth-authorization-server/default/authorize")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<Value>().unwrap();

        assert!(response.get("issuer").is_some());
        assert!(response.get("jwks_uri").is_some());
    }
}
