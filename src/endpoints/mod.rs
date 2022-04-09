use openidconnect::{core::CoreGenderClaim, UserInfoClaims};
use rocket::http::Status;
use rocket::response::status::NotFound;
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::State;
use web3_login::claims::{Claims, ClaimsMutex};
use web3_login::config::Config;
use web3_login::token::{Tokens, Web3TokenResponse};
use web3_login::userinfo::userinfo;

use crate::bearer::Bearer;

pub mod account_endpoints;
pub mod nft_endpoints;

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

#[allow(unused_variables)]
#[get("/<realm>/token?<code>")]
pub fn get_token(
    tokens: &State<Tokens>,
    realm: String,
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
        assert!(response
            .headers()
            .get("Location")
            .next()
            .unwrap()
            .starts_with("https://example.com/?code="));
    }
}
