use async_trait::async_trait;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::{
    extract::{FromRequest, Query, Request, State},
    response::{IntoResponse, Response},
    Form, Json, RequestExt,
};
use serde::{Deserialize, Serialize};

use crate::prelude::Server;

use super::TokenTrait;

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
    JsonOrForm(payload): JsonOrForm<TokenParams>,
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

pub struct JsonOrForm<T>(T);

#[async_trait]
impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<()>,
    Form<T>: FromRequest<()>,
    T: 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                let Json(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self(payload));
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                let Form(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self(payload));
            }
        }

        Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())
    }
}
