use openidconnect::core::CoreGenderClaim;
use openidconnect::{AdditionalClaims, EndUserName, StandardClaims, SubjectIdentifier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub account: String,
    pub nonce: String,
    pub signature: String,
    pub chain_id: i32,
    pub node: String,
    pub contract: String,
}

impl AdditionalClaims for Claims {}

#[derive(Clone)]
pub struct ClaimsMutex {
    pub standard_claims: Arc<Mutex<HashMap<String, StandardClaims<CoreGenderClaim>>>>,
    pub additional_claims: Arc<Mutex<HashMap<String, Claims>>>,
}

pub fn standard_claims(account: &str) -> StandardClaims<CoreGenderClaim> {
    StandardClaims::new(SubjectIdentifier::new(account.to_string()))
        .set_name(Some(EndUserName::new("anonymous".to_string()).into()))
}

pub fn additional_claims(
    account: &str,
    nonce: &str,
    signature: &str,
    chain_id: &i32,
    node: &str,
    contract: &str,
) -> Claims {
    Claims {
        account: account.to_string(),
        nonce: nonce.to_string(),
        signature: signature.to_string(),
        chain_id: *chain_id,
        node: node.to_string(),
        contract: contract.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_claims_mutex() {
        let claims: ClaimsMutex = ClaimsMutex {
            standard_claims: Arc::new(Mutex::new(HashMap::new())),
            additional_claims: Arc::new(Mutex::new(HashMap::new())),
        };

        let locked = claims.additional_claims.lock().unwrap();
        assert_eq!(locked.len(), 0);
    }
}
