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
            .append_pair("chain_id", &chain_id.clone().unwrap_or(realm.clone()))
            .append_pair("contract", &contract.unwrap_or(client_id.clone()));
        return Ok(Redirect::temporary(url.to_string()));
    };

    if nonce.is_none() {
        return Ok(Redirect::temporary("/400.html?message=nonce%20missing"));
    }

    if signature.is_none() {
        return Ok(Redirect::temporary("/400.html?message=signature%20missing"));
    }

    let redirect_uri = Url::parse(&redirect_uri);

    if redirect_uri.is_err() {
        return Ok(Redirect::temporary("/400.html?message=wrong%20redirect%20uri"));
    }

    let mut redirect_uri = redirect_uri.unwrap();

    if !validate_signature(
        account.clone().unwrap(),
        nonce.clone().unwrap(),
        signature.clone().unwrap(),
    ) {
        return Ok(Redirect::temporary("/400.html?message=no%20valide%20signature"));
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
            return Ok(Redirect::temporary("/401.html"));
        }
    } else {
        return Ok(Redirect::temporary("/401.html"));
    }

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
        realm.unwrap_or("default".into()),
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

#[cfg(test)]
mod authorize_tests {
    use crate::rocket;
    use rocket::http::Status;
    use rocket::local::blocking::Client;
    use std::collections::HashMap;
    use url::Url;

    #[test]
    fn redirect() {
        let client_id = "0xa0d4E5CdD89330ef9d0d1071247909882f0562eA";
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=kovan&redirect_uri=unused",
                client_id
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        let response_url = Url::parse(response.headers().get("Location").next().unwrap()).unwrap();
        let mut path_segments = response_url.path_segments().unwrap();
        assert_eq!(path_segments.next(), Some(""));

        let params: HashMap<String, String> = response_url
            .query()
            .map(|v| {
                url::form_urlencoded::parse(v.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_else(HashMap::new);

        assert_eq!(params.get("realm"), Some(&"kovan".to_string()));

        assert_eq!(params.get("chain_id"), Some(&"kovan".to_string()));

        assert_eq!(params.get("contract"), Some(&client_id.to_string()));
    }

    #[test]
    fn wrong_redirect_uri() {
        let client_id = "foo";
        let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=wrong_uri&nonce={}&contract={}&account={}&signature={}",
                client_id, nonce, contract, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        //assert_eq!(response.into_string().unwrap(), "wrong redirect uri");
    }

    #[test]
    fn test_state() {
        let client_id = "foo";
        let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();
        let state = "state".to_string();
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&contract={}&account={}&signature={}&state={}",
                client_id, nonce, contract, account, signature, state
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

        assert_eq!(params.get("state"), Some(&state));
    }

    #[test]
    fn test_code_id_token() {
        let client_id = "foo";
        let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();
        let state = "state".to_string();
        let code = "code".to_string();
        let id_token = "id_token".to_string();
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&contract={}&account={}&signature={}&state={}&code={}&id_token={}&response_type=code+id_token",
                client_id, nonce, contract, account, signature, state, code, id_token
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

        assert_eq!(params.get("state"), Some(&state));
        assert!(params.get("code").is_some());
        assert!(params.get("id_token").is_some());
    }

    #[test]
    fn redirect_with_contract() {
        let client_id = "foo";
        let contract = "0xa0d4E5CdD89330ef9d0d1071247909882f0562eA";
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=kovan&redirect_uri=unused&contract={}",
                client_id, contract
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        println!("{:?}", response);
        let response_url = Url::parse(response.headers().get("Location").next().unwrap()).unwrap();
        let mut path_segments = response_url.path_segments().unwrap();
        assert_eq!(path_segments.next(), Some(""));

        let params: HashMap<String, String> = response_url
            .query()
            .map(|v| {
                url::form_urlencoded::parse(v.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_else(HashMap::new);

        assert_eq!(params.get("realm"), Some(&"kovan".to_string()));
        assert_eq!(params.get("chain_id"), Some(&"kovan".to_string()));
        assert_ne!(params.get("contract"), Some(&client_id.to_string()));
        assert_eq!(params.get("contract"), Some(&contract.to_string()));
    }

    #[test]
    fn account_no_signature() {
        let client_id = "foo";
        let contract = "0xa0d4E5CdD89330ef9d0d1071247909882f0562eA";
        let account = "0xa0d4E5CdD89330ef9d0d1071247909882f0562eA";
        let signature = "";
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=kovan&redirect_uri=https://example.com&contract={}&account={}",
                client_id, contract, account
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=kovan&redirect_uri=https://example.com&nonce=42&contract={}&account={}",
                client_id, contract, account
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=kovan&redirect_uri=https://example.com&nonce=42&contract={}&account={}&signature={}",
                client_id, contract, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
    }

    #[test]
    fn account_valid_signature() {
        let client_id = "foo";
        let contract = "0xa0d4E5CdD89330ef9d0d1071247909882f0562eA";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&contract={}&account={}&signature={}",
                client_id, nonce, contract, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
    }

    #[test]
    fn account_not_owner() {
        let client_id = "foo";
        let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";
        let account = "0x4b895d519f01c2be9a1472f9333b597017f41495".to_string();
        let nonce = "L3xt4w3hZqhyMbKqSjLDhY5bXID8UMItk_ILdutKb-I".to_string();
        let signature = "0x620335720244ea6317d39a8f70d0df98d5e8299ad64d0b423f136002fa4636dc2bc1c75c7b6c9a09669e01d48bf91ad78ebafb82d2065573be90f2ec2480874f1c".to_string();

        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&contract={}&account={}&signature={}",
                client_id, nonce, contract, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        //assert_eq!(response.into_string().unwrap(), "account is no owner");
    }

    #[test]
    fn account_is_owner() {
        let client_id = "foo";
        let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client
            .get(format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&contract={}&account={}&signature={}",
                client_id, nonce, contract, account, signature
            ))
            .dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
    }
}
