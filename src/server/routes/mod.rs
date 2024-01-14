use crate::{claims::Claims, traits::*};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_auth::AuthBearer;
use openidconnect::{core::CoreGenderClaim, UserInfoClaims};

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

pub async fn get_authorize(app: State<Server>) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.authorize() {
        Ok(authorize) => Ok(Json(authorize)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_token(
    app: State<Server>,
    code: String,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match app.get_token(code) {
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
