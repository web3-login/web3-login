use crate::authorize::{AuthScope, AuthorizeOutcome};
use crate::{claims::Claims, traits::*};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, options, post};
use axum::Json;
use axum_auth::AuthBearer;
use axum_extra::extract::OptionalPath;
use openidconnect::{core::CoreGenderClaim, UserInfoClaims};
use serde::{Deserialize, Serialize};

pub mod token;

use super::Server;
pub use token::*;

pub async fn get_providers(app: State<Server>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "providers": app.config.node_provider
    }))
}

pub async fn get_realms(app: State<Server>) -> Json<serde_json::Value> {
    let realms: Vec<String> = crate::config::realms(&app.config);
    Json(serde_json::json!({
        "realms": realms
    }))
}

pub async fn get_frontend(app: State<Server>) -> Redirect {
    Redirect::temporary(&app.config.frontend_host)
}

pub async fn get_user_info(
    AuthBearer(token): AuthBearer,
    app: State<Server>,
) -> Result<Json<Option<UserInfoClaims<Claims, CoreGenderClaim>>>, StatusCode> {
    match app.userinfo(token) {
        Ok(info) => Ok(Json(info)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn options_user_info() {}

pub async fn get_jwk(app: State<Server>) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.jwk() {
        Ok(jwk) => Ok(Json(jwk)),
        Err(err) => {
            log::error!("Error getting JWK: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_openid_configuration(
    app: State<Server>,
    OptionalPath(auth_scope): OptionalPath<AuthScope>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.openid_configuration(auth_scope.unwrap_or(AuthScope::Account)) {
        Ok(openid_configuration) => Ok(Json(openid_configuration)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_authorize_configuration(
    app: State<Server>,
    OptionalPath(auth_scope): OptionalPath<AuthScope>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.authorize_configuration(auth_scope.unwrap_or(AuthScope::Account)) {
        Ok(authorize) => Ok(Json(authorize)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub nonce: Option<String>,
    pub account: Option<String>,
    pub signature: Option<String>,
    pub realm: Option<String>,
    pub chain_id: Option<String>,
    pub contract: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub async fn get_authorize(
    app: State<Server>,
    params: Query<AuthorizeParams>,
    OptionalPath(auth_scope): OptionalPath<AuthScope>,
) -> impl IntoResponse {
    match app
        .authorize(
            auth_scope.unwrap_or(AuthScope::Account),
            params.realm.clone(),
            params.client_id.clone(),
            params.redirect_uri.clone(),
            params.state.clone(),
            params.response_type.clone(),
            params.response_mode.clone(),
            params.nonce.clone(),
            params.account.clone(),
            params.signature.clone(),
            params.chain_id.clone(),
            params.contract.clone(),
            params.code_challenge.clone(),
            params.code_challenge_method.clone(),
        )
        .await
    {
        Ok(authorize) => match authorize {
            AuthorizeOutcome::RedirectNeeded(redirect) => {
                Redirect::temporary(&redirect).into_response()
            }
            AuthorizeOutcome::Error(message) => Redirect::temporary(&format!(
                "{}/400.html?message={}",
                app.config.ext_hostname, message
            ))
            .into_response(),
            AuthorizeOutcome::Success(auth_data) => {
                Json(serde_json::to_value(auth_data).unwrap()).into_response()
            }
            AuthorizeOutcome::Denied(message) => Redirect::temporary(&format!(
                "{}/401.html?message={}",
                app.config.ext_hostname, message
            ))
            .into_response(),
        },
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub fn oidc_routes() -> axum::Router<Server> {
    axum::Router::new()
        .route("/userinfo", get(get_user_info))
        .route("/userinfo", options(options_user_info))
        .route("/jwk", get(get_jwk))
        .route(
            "/.well-known/openid-configuration",
            get(get_openid_configuration),
        )
        .route(
            "/.well-known/oauth-authorization-server/authorize",
            get(get_authorize_configuration),
        )
        .route("/token", get(get_token))
        .route("/token", post(post_token))
        .route("/authorize", get(get_authorize))
}
