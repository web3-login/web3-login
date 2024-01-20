use crate::{
    authorize::{AuthScope, AuthorizeImpl, AuthorizeOutcome},
    claims::ClaimsMutex,
    config::Config,
    jwk::JWKImpl,
    token::{TokenImpl, Tokens},
    traits::{AuthorizeTrait, JWKTrait, OIDCTrait, TokenTrait, UserInfoTrait, WellKnownTrait},
    userinfo::UserInfoImpl,
    well_known::WellKnownImpl,
};
use axum::{routing::get, Router};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
};
use tower_http::services::{ServeDir, ServeFile};

use self::routes::{get_frontend, get_providers, get_realms, oidc_routes};

pub mod routes;

pub fn router(app: Server) -> Result<Router, Box<dyn Error>> {
    let router = Router::new()
        .route("/frontend", get(get_frontend))
        .route("/providers", get(get_providers))
        .route("/realms", get(get_realms))
        .nest("/", oidc_routes())
        .nest("/:realm/", oidc_routes())
        .nest("/account", oidc_routes())
        .nest("/account/:realm/", oidc_routes())
        .nest_service("/index.html", ServeFile::new("static/index.html"))
        .nest_service("/favicon.ico", ServeFile::new("static/favicon.ico"))
        .nest_service("/index.css", ServeDir::new("static/index.css"))
        .nest_service("/index.js", ServeDir::new("static/index.js"))
        .nest_service("/400.html", ServeFile::new("static/400.html"))
        .nest_service("/401.html", ServeFile::new("static/401.html"))
        .route_service("/", ServeFile::new("static/index.html"))
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
    fn openid_configuration(
        &self,
        auth_scope: AuthScope,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        self.well_known.openid_configuration(auth_scope)
    }

    fn authorize_configuration(
        &self,
        auth_scope: AuthScope,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        self.well_known.authorize_configuration(auth_scope)
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
        auth_scope: AuthScope,
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
    ) -> Result<AuthorizeOutcome, Box<dyn Error>> {
        self.authorize.authorize(
            auth_scope,
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
