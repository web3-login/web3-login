use std::error::Error;

use crate::{
    claims::{Claims, ClaimsMutex},
    traits::UserInfoTrait,
};
use openidconnect::{core::CoreGenderClaim, UserInfoClaims};

#[derive(Clone)]
pub struct UserInfoImpl {
    claims: ClaimsMutex,
}

impl UserInfoImpl {
    pub fn new(claims: ClaimsMutex) -> Self {
        Self { claims }
    }
}

impl UserInfoTrait for UserInfoImpl {
    fn userinfo(
        &self,
        access_token: String,
    ) -> Result<Option<UserInfoClaims<Claims, CoreGenderClaim>>, Box<dyn Error>> {
        Ok(userinfo(&self.claims, access_token))
    }
}

pub fn userinfo(
    claims: &ClaimsMutex,
    access_token: String,
) -> Option<UserInfoClaims<Claims, CoreGenderClaim>> {
    let locked = claims.standard_claims.lock().unwrap();
    let standard_claims = locked.get(&access_token);

    let locked = claims.additional_claims.lock().unwrap();
    let additional_claims = locked.get(&access_token);

    match (standard_claims, additional_claims) {
        (Some(standard_claims), Some(additional_claims)) => {
            let userinfo_claims =
                UserInfoClaims::new(standard_claims.clone(), additional_claims.clone());
            Some(userinfo_claims)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_no_userinfo() {
        let claims: ClaimsMutex = ClaimsMutex {
            standard_claims: Arc::new(Mutex::new(HashMap::new())),
            additional_claims: Arc::new(Mutex::new(HashMap::new())),
        };
        assert!(userinfo(&claims, "wrong_access_token".into()).is_none());
    }
}
