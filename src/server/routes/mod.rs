use crate::authorize::AuthorizeOutcome;
use crate::{claims::Claims, traits::*};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use axum_auth::AuthBearer;
use openidconnect::{core::CoreGenderClaim, UserInfoClaims};
use serde::{Deserialize, Serialize};

use super::Server;

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
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_openid_configuration(
    app: State<Server>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.openid_configuration() {
        Ok(openid_configuration) => Ok(Json(openid_configuration)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_authorize_configuration(
    app: State<Server>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.authorize_configuration() {
        Ok(authorize) => Ok(Json(authorize)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenParams {
    pub code: String,
}

pub async fn get_token(
    app: State<Server>,
    params: Query<TokenParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.get_token(params.code.clone()) {
        Ok(token) => Ok(Json(token)),
        Err(err) => {
            if err.to_string() == "Invalid Code" {
                Err(StatusCode::BAD_REQUEST)
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub async fn post_token(
    app: State<Server>,
    Json(payload): Json<TokenParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.get_token(payload.code) {
        Ok(token) => Ok(Json(token)),
        Err(err) => {
            if err.to_string() == "Invalid Code" {
                Err(StatusCode::BAD_REQUEST)
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
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
}

pub async fn get_authorize(
    app: State<Server>,
    params: Query<AuthorizeParams>,
) -> impl IntoResponse {
    match app.authorize(
        None,
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
    ) {
        Ok(authorize) => match authorize {
            AuthorizeOutcome::RedirectNeeded(redirect) => {
                Redirect::temporary(&redirect).into_response()
            }
            AuthorizeOutcome::Error(error) => {
                Redirect::temporary(&format!("/400.html?message={}", error)).into_response()
            }
            AuthorizeOutcome::Success(auth_data) => {
                Json(serde_json::to_value(auth_data).unwrap()).into_response()
            }
        },
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
