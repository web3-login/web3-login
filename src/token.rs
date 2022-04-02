use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreTokenType,
};
use openidconnect::{EmptyExtraTokenFields, IdTokenFields, StandardTokenResponse};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::claims::Claims;

pub type Web3IdTokenFields = IdTokenFields<
    Claims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

pub type Web3TokenResponse = StandardTokenResponse<Web3IdTokenFields, CoreTokenType>;

pub struct Tokens {
    pub muted: Arc<Mutex<HashMap<String, Web3TokenResponse>>>,
    pub bearer: Arc<Mutex<HashMap<String, String>>>,
}
