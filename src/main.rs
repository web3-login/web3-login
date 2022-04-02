#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_include_static_resources;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::serde::json::Json;
use rocket::{Request, Response, State};
use rocket_include_static_resources::{EtagIfNoneMatch, StaticContextManager, StaticResponse};

mod bearer;
mod endpoints;
mod tests;

use endpoints::account_endpoints;
use endpoints::nft_endpoints;

use web3_login::claims::ClaimsMutex;
use web3_login::config::{realms, Config};
use web3_login::token::Tokens;

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
    Json(realms(config))
}

#[launch]
pub fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let mut config: Config = figment.extract().expect("config");
    config.rsa_pem = Some(include_str!("../do-not-use.pem").to_string());

    let tokens: Tokens = Tokens {
        muted: Arc::new(Mutex::new(HashMap::new())),
        bearer: Arc::new(Mutex::new(HashMap::new())),
    };

    let claims: ClaimsMutex = ClaimsMutex {
        standard_claims: Arc::new(Mutex::new(HashMap::new())),
        additional_claims: Arc::new(Mutex::new(HashMap::new())),
    };

    rocket
        .attach(static_resources_initializer!(
            "indexjs" => "static/index.js",
            "indexcss" => "static/index.css",
            "index" => ("static", "index.html"),
        ))
        .attach(CORS)
        .mount("/", routes![cached_indexjs, cached_indexcss])
        .mount("/", routes![default_index, get_providers, get_realms])
        .mount(
            "/account/",
            routes![
                account_endpoints::get_jwk,
                account_endpoints::get_openid_configuration,
                account_endpoints::get_oauth_authorization_server,
                endpoints::get_userinfo,
                endpoints::get_token
            ],
        )
        .mount(
            "/nft/",
            routes![
                nft_endpoints::get_jwk,
                nft_endpoints::get_openid_configuration,
                nft_endpoints::get_oauth_authorization_server,
                endpoints::get_userinfo,
                endpoints::get_token
            ],
        )
        .manage(config)
        .manage(claims)
        .manage(tokens)
        .register("/", catchers![unauthorized])
}
