use std::error::Error;

use openidconnect::{core::CoreGenderClaim, UserInfoClaims};
use serde_json::Value;

use crate::claims::Claims;
pub trait OIDCTrait: Send + Sync + UserInfoTrait + JWKTrait {}

pub trait UserInfoTrait: Send + Sync {
    fn userinfo(
        &self,
        access_token: String,
    ) -> Result<Option<UserInfoClaims<Claims, CoreGenderClaim>>, Box<dyn Error>>;
}

pub trait JWKTrait: Send + Sync {
    fn jwk(&self) -> Result<Value, Box<dyn Error>>;
}

pub trait WellKnownTrait: Send + Sync {
    fn openid_configuration(&self) -> Result<Value, Box<dyn Error>>;

    fn authorize_configuration(&self) -> Result<Value, Box<dyn Error>>;
}

pub trait TokenTrait: Send + Sync {
    fn get_token(&self, code: String) -> Result<Value, Box<dyn Error>>;
}

pub trait AuthorizeTrait: Send + Sync {
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
    ) -> Result<Value, Box<dyn Error>>;
}
