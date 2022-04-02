#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_include_static_resources;

use std::collections::HashMap;

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::serde::json::Json;
use rocket::{Request, Response, State};
use rocket_include_static_resources::{EtagIfNoneMatch, StaticContextManager, StaticResponse};

mod account_endpoints;
mod nft_endpoints;
mod tests;

use web3_login::config::{realms, Config};

cached_static_response_handler! {
    259_200;
    "/index.js" => cached_indexjs => "indexjs",
    "/index.css" => cached_indexcss => "indexcss",
}

#[get("/")]
fn default_index(
    static_resources: &State<StaticContextManager>,
    etag_if_none_match: EtagIfNoneMatch,
) -> StaticResponse {
    static_resources.build(&etag_if_none_match, "index")
}

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Attaching CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[catch(401)]
fn unauthorized() -> String {
    "We could not find a token for your address on this contract.".to_string()
}

#[get("/providers")]
fn get_providers(config: &State<Config>) -> Json<HashMap<String, String>> {
    Json(config.node_provider.clone())
}

#[get("/realms")]
fn get_realms(config: &State<Config>) -> Json<Vec<String>> {
    let config = config.clone();
    Json(realms(&config))
}

#[launch]
pub fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let mut config: Config = figment.extract().expect("config");
    config.rsa_pem = Some(include_str!("../do-not-use.pem").to_string());

    rocket
        .attach(static_resources_initializer!(
            "indexjs" => "static/index.js",
            "indexcss" => "static/index.css",
            "index" => ("static", "index.html"),
        ))
        .attach(CORS)
        .mount("/", routes![cached_indexjs, cached_indexcss])
        .mount(
            "/",
            routes![
                default_index,
                get_providers,
                get_realms,
                account_endpoints::get_jwk
            ],
        )
        .mount("/account/", routes![account_endpoints::get_jwk])
        .mount("/nft/", routes![nft_endpoints::get_jwk])
        .manage(config)
        .register("/", catchers![unauthorized])
}
