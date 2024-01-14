use crate::{
    claims::ClaimsMutex,
    config::Config,
    jwk::JWKImpl,
    token::{TokenImpl, Tokens},
    traits::{JWKTrait, OIDCTrait, TokenTrait, UserInfoTrait, WellKnownTrait},
    userinfo::UserInfoImpl,
    well_known::WellKnownImpl,
};
use axum::{routing::get, Router};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
};

use self::routes::{get_authorize, get_jwk, get_openid_configuration, get_token, get_user_info};

pub mod routes;

pub fn router(app: Server) -> Result<Router, Box<dyn Error>> {
    let router = Router::new()
        .route("/userinfo", get(get_user_info))
        .route("/jwk", get(get_jwk))
        .route(
            "/.well-known/openid-configuration",
            get(get_openid_configuration),
        )
        .route(
            "/.well-known/oauth-authorization-server/authorize",
            get(get_authorize),
        )
        .route("/token", get(get_token))
        .with_state(app);
    Ok(router)
}

#[derive(Clone)]
pub struct Server {
    config: Config,
    claims: ClaimsMutex,
    tokens: Tokens,
    user_info: Arc<Box<dyn UserInfoTrait>>,
    jwk: Arc<Box<dyn JWKTrait>>,
    well_known: Arc<Box<dyn WellKnownTrait>>,
    token: Arc<Box<dyn TokenTrait>>,
}

impl OIDCTrait for Server {}

impl Server {
    pub fn new(config: Config) -> Self {
        let claims: ClaimsMutex = ClaimsMutex {
            standard_claims: Arc::new(Mutex::new(HashMap::new())),
            additional_claims: Arc::new(Mutex::new(HashMap::new())),
        };

        let tokens: Tokens = Tokens {
            muted: Arc::new(Mutex::new(HashMap::new())),
            bearer: Arc::new(Mutex::new(HashMap::new())),
        };

        let user_info: Arc<Box<dyn UserInfoTrait>> =
            Arc::new(Box::new(UserInfoImpl::new(claims.clone())));
        let jwk: Arc<Box<dyn JWKTrait>> = Arc::new(Box::new(JWKImpl::new(config.clone())));

        let well_known: Arc<Box<dyn WellKnownTrait>> =
            Arc::new(Box::new(WellKnownImpl::new(config.clone())));

        let token: Arc<Box<dyn TokenTrait>> = Arc::new(Box::new(TokenImpl::new(tokens.clone())));

        Self {
            config,
            claims,
            tokens,
            user_info,
            jwk,
            well_known,
            token,
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

impl WellKnownTrait for Server {
    fn openid_configuration(&self) -> Result<serde_json::Value, Box<dyn Error>> {
        self.well_known.openid_configuration()
    }

    fn authorize(&self) -> Result<serde_json::Value, Box<dyn Error>> {
        self.well_known.authorize()
    }
}

impl TokenTrait for Server {
    fn get_token(&self, code: String) -> Result<serde_json::Value, Box<dyn Error>> {
        self.token.get_token(code)
    }
}

#[cfg(test)]
mod tests;
