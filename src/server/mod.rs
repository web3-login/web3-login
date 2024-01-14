use crate::{
    authorize::AuthorizeImpl,
    claims::ClaimsMutex,
    config::Config,
    jwk::JWKImpl,
    token::{TokenImpl, Tokens},
    traits::{AuthorizeTrait, JWKTrait, OIDCTrait, TokenTrait, UserInfoTrait, WellKnownTrait},
    userinfo::UserInfoImpl,
    well_known::WellKnownImpl,
};
use axum::{
    response::IntoResponse,
    routing::{get, options, post},
    Router,
};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
};
use tower_http::services::{ServeDir, ServeFile};

use self::routes::{
    get_authorize, get_authorize_configuration, get_jwk, get_openid_configuration, get_token,
    get_user_info, options_user_info, post_token,
};

pub mod routes;

pub fn router(app: Server) -> Result<Router, Box<dyn Error>> {
    let router = Router::new()
        .route("/userinfo", get(get_user_info))
        .route("/:realm/userinfo", get(get_user_info))
        .route("/userinfo", options(options_user_info))
        .route("/:realm/userinfo", options(options_user_info))
        .route("/jwk", get(get_jwk))
        .route("/:realm/jwk", get(get_jwk))
        .route(
            "/.well-known/openid-configuration",
            get(get_openid_configuration),
        )
        .route(
            "/:realm/.well-known/openid-configuration",
            get(get_openid_configuration),
        )
        .route(
            "/.well-known/oauth-authorization-server/authorize",
            get(get_authorize_configuration),
        )
        .route(
            "/:realm/.well-known/oauth-authorization-server/authorize",
            get(get_authorize_configuration),
        )
        .route("/token", get(get_token))
        .route("/:realm/token", get(get_token))
        .route("/token", post(post_token))
        .route("/:realm/token", post(post_token))
        .route("/authorize", get(get_authorize))
        .route("/:realm/authorize", get(get_authorize))
        .nest_service("/index.html", ServeFile::new("static/index.html"))
        .nest_service("/favicon.ico", ServeFile::new("static/favicon.ico"))
        .nest_service("/index.css", ServeDir::new("static/index.css"))
        .nest_service("/index.js", ServeDir::new("static/index.js"))
        .nest_service("/400.html", ServeFile::new("static/400.html"))
        .nest_service("/401.html", ServeFile::new("static/401.html"))
        .with_state(app);
    Ok(router)
}

#[derive(Clone)]
pub struct Server {
    pub config: Config,
    pub claims: ClaimsMutex,
    pub tokens: Tokens,
    pub user_info: Arc<Box<dyn UserInfoTrait>>,
    pub jwk: Arc<Box<dyn JWKTrait>>,
    pub well_known: Arc<Box<dyn WellKnownTrait>>,
    pub token: Arc<Box<dyn TokenTrait>>,
    pub authorize: Arc<Box<dyn AuthorizeTrait>>,
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

        let authorize: Arc<Box<dyn AuthorizeTrait>> = Arc::new(Box::new(AuthorizeImpl::new(
            config.clone(),
            claims.clone(),
            tokens.clone(),
        )));
        Self {
            config,
            claims,
            tokens,
            user_info,
            jwk,
            well_known,
            token,
            authorize,
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

    fn authorize_configuration(&self) -> Result<serde_json::Value, Box<dyn Error>> {
        self.well_known.authorize_configuration()
    }
}

impl TokenTrait for Server {
    fn get_token(&self, code: String) -> Result<serde_json::Value, Box<dyn Error>> {
        self.token.get_token(code)
    }
}

impl AuthorizeTrait for Server {
    fn authorize(
        &self,
        realm: Option<String>,
        client_id: String,
        redirect_uri: String,
        state: Option<String>,
        response_type: Option<String>,
        response_mode: Option<String>,
        nonce: Option<String>,
        account: Option<String>,
        signature: Option<String>,
        chain_id: Option<String>,
        contract: Option<String>,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        self.authorize.authorize(
            realm,
            client_id,
            redirect_uri,
            state,
            response_type,
            response_mode,
            nonce,
            account,
            signature,
            chain_id,
            contract,
        )
    }
}

#[cfg(test)]
pub mod tests;
