#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_include_static_resources;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Header, Status};
use rocket::response::Redirect;
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
    "/favicon.ico" => cached_favicon => "favicon",
    "/400.html" => cached_400 => "error400",
    "/401.html" => cached_401 => "error401",
}

#[get("/")]
fn default_index(
    static_resources: &State<StaticContextManager>,
    etag_if_none_match: EtagIfNoneMatch,
) -> StaticResponse {
    static_resources.build(&etag_if_none_match, "index")
}

#[allow(unused_variables)]
#[get("/<realm>")]
fn index(
    static_resources: &State<StaticContextManager>,
    etag_if_none_match: EtagIfNoneMatch,
    realm: String,
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
fn unauthorized() -> Redirect {
    Redirect::temporary("/401.html")
}

#[catch(400)]
fn bad_request() -> Redirect {
    Redirect::temporary("/400.html")
}

#[get("/providers")]
fn get_providers(config: &State<Config>) -> Json<HashMap<String, String>> {
    Json(config.node_provider.clone())
}

#[get("/realms")]
fn get_realms(config: &State<Config>) -> Json<Vec<String>> {
    Json(realms(config))
}

#[get("/frontend")]
pub async fn get_frontend(config: &State<Config>) -> Result<Redirect, (Status, String)> {
    Ok(Redirect::temporary(config.frontend_host.to_string()))
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
            "favicon" => "static/favicon.ico",
            "error400" => "static/400.html",
            "error401" => "static/401.html",
            "index" => ("static", "index.html"),
        ))
        .attach(CORS)
        .mount(
            "/",
            routes![
                cached_indexjs,
                cached_indexcss,
                cached_favicon,
                cached_400,
                cached_401
            ],
        )
        .mount(
            "/",
            routes![
                default_index,
                get_providers,
                get_realms,
                get_frontend,
                endpoints::get_default_jwk,
                endpoints::get_default_authorize,
                endpoints::get_default_userinfo,
                endpoints::get_openid_configuration,
                endpoints::options_default_userinfo,
                endpoints::options_userinfo,
                endpoints::get_default_token
            ],
        )
        .mount(
            "/account/",
            routes![cached_indexjs, cached_indexcss, cached_favicon],
        )
        .mount(
            "/account/",
            routes![
                index,
                endpoints::get_jwk,
                endpoints::get_default_jwk,
                endpoints::get_oauth_authorization_server,
                account_endpoints::get_openid_configuration,
                account_endpoints::get_oauth_authorization_server,
                endpoints::get_userinfo,
                endpoints::get_token,
                account_endpoints::get_authorize,
                account_endpoints::get_default_authorize
            ],
        )
        .mount(
            "/nft/",
            routes![cached_indexjs, cached_indexcss, cached_favicon],
        )
        .mount(
            "/nft/",
            routes![
                index,
                endpoints::get_jwk,
                endpoints::get_default_jwk,
                nft_endpoints::get_openid_configuration,
                nft_endpoints::get_oauth_authorization_server,
                endpoints::get_userinfo,
                endpoints::get_token,
                nft_endpoints::get_authorize,
                nft_endpoints::get_default_authorize
            ],
        )
        .manage(config)
        .manage(claims)
        .manage(tokens)
        .register("/", catchers![bad_request, unauthorized])
}
