use crate::web3::validate_signature;
use async_trait::async_trait;

mod authorize_impl;
pub use authorize_impl::*;

mod authorize_error;
pub use authorize_error::*;

mod nft_authorize;
pub use nft_authorize::*;

mod web3_authorize;
use serde::{Deserialize, Serialize};
pub use web3_authorize::*;

#[cfg_attr(not(feature = "wasm"), async_trait)]
#[cfg_attr(feature="wasm", async_trait(?Send))]
pub trait Authorize {
    fn get_account(&self) -> &Option<String>;
    fn get_nonce(&self) -> &Option<String>;
    fn get_signature(&self) -> &Option<String>;

    fn check_account(&self) -> Result<(), AuthorizeError> {
        match self.get_account() {
            Some(_) => Ok(()),
            None => Err(AuthorizeError::AccountError),
        }
    }

    fn check_nonce(&self) -> Result<(), AuthorizeError> {
        match self.get_nonce() {
            Some(_) => Ok(()),
            None => Err(AuthorizeError::NonceError),
        }
    }

    fn check_signature(&self) -> Result<(), AuthorizeError> {
        match self.get_signature() {
            Some(_) => (),
            None => return Err(AuthorizeError::SignatureError),
        };
        let account = self.get_account().as_ref().unwrap().to_string();
        let nonce = self.get_nonce().as_ref().unwrap().to_string();
        let signature = self.get_signature().as_ref().unwrap().to_string();
        match validate_signature(account, nonce, signature) {
            true => Ok(()),
            false => Err(AuthorizeError::SignatureError),
        }
    }

    async fn authorize(&self) -> Result<(), AuthorizeError> {
        self.check_account()?;
        self.check_nonce()?;
        self.check_signature()?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AuthorizeOutcome {
    RedirectNeeded(String),
    Error(String),
    Success(AuthData),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthData {
    pub code: String,
    pub id_token: Option<String>,
}
