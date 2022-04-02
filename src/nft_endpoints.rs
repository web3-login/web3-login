use rocket::serde::json::{Json, Value};
use rocket::State;
use web3_login::config::Config;
use web3_login::jwk::jwk;

#[get("/jwk")]
pub fn get_jwk(config: &State<Config>) -> Json<Value> {
    Json(jwk(config, "".into()))
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
        let response = client.get("/nft/jwk").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_json::<Value>().unwrap();

        assert!(response.get("keys").is_some());
    }
}
