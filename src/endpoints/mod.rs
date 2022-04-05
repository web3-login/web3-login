use openidconnect::{core::CoreGenderClaim, UserInfoClaims};
use rocket::response::status::NotFound;
use rocket::serde::json::Json;
use rocket::State;
use web3_login::claims::{Claims, ClaimsMutex};
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
}
