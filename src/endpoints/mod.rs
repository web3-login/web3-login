use openidconnect::{core::CoreGenderClaim, UserInfoClaims};
use rocket::response::status::NotFound;
use rocket::serde::json::Json;
use rocket::State;
use web3_login::claims::{Claims, ClaimsMutex};
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

#[cfg(test)]
mod tests {
    use crate::rocket;
    use rocket::http::{Header, Status};
    use rocket::local::blocking::Client;

    #[test]
    fn test_no_userinfo() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client.get("/nft/default/userinfo").dispatch();
        assert_eq!(response.status(), Status::BadRequest);

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
