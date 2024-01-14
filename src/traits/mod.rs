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
