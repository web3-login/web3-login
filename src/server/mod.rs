use crate::{
    claims::ClaimsMutex,
    config::Config,
    jwk::JWKImpl,
    traits::{JWKTrait, OIDCTrait, UserInfoTrait},
    userinfo::UserInfoImpl,
};
use axum::{routing::get, Router};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
};

use self::routes::{get_jwk, get_user_info};

pub mod routes;

pub fn router(app: Server) -> Result<Router, Box<dyn Error>> {
    let router = Router::new()
        .route("/userinfo", get(get_user_info))
        .route("/jwk", get(get_jwk))
        .with_state(app);
    Ok(router)
}

#[derive(Clone)]
pub struct Server {
    config: Config,
    claims: ClaimsMutex,
    user_info: Arc<Box<dyn UserInfoTrait>>,
    jwk: Arc<Box<dyn JWKTrait>>,
}

impl OIDCTrait for Server {}

impl Server {
    pub fn new(config: Config) -> Self {
        let claims: ClaimsMutex = ClaimsMutex {
            standard_claims: Arc::new(Mutex::new(HashMap::new())),
            additional_claims: Arc::new(Mutex::new(HashMap::new())),
        };
        let user_info: Arc<Box<dyn UserInfoTrait>> =
            Arc::new(Box::new(UserInfoImpl::new(claims.clone())));
        let jwk: Arc<Box<dyn JWKTrait>> = Arc::new(Box::new(JWKImpl::new(config.clone())));

        Self {
            config,
            claims,
            user_info,
            jwk,
        }
    }
}

impl JWKTrait for Server {
    fn jwk(&self) -> Result<serde_json::Value, Box<dyn Error>> {
        self.jwk.jwk()
    }
}

impl UserInfoTrait for Server {
    fn userinfo(
        &self,
        access_token: String,
    ) -> Result<
        Option<
            openidconnect::UserInfoClaims<
                crate::claims::Claims,
                openidconnect::core::CoreGenderClaim,
            >,
        >,
        Box<dyn Error>,
    > {
        Ok(self.user_info.userinfo(access_token)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_router() {
        let config = Config::default();
        let server = Server::new(config);
        let router = router(server).unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/userinfo")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_jwk() {
        let mut config = Config::default();
        config.rsa_pem = Some(include_str!("../../do-not-use.pem").to_string());
        let server = Server::new(config);
        let router = router(server).unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/jwk")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
