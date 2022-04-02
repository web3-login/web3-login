use rocket::serde::json::{Json, Value};
use rocket::State;
use web3_login::config::Config;
use web3_login::jwk::jwk;

#[get("/jwk")]
pub fn get_jwk(config: &State<Config>) -> Json<Value> {
    Json(jwk(config, "".into()))
}
