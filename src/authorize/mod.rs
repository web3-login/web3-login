use async_trait::async_trait;
use serde::{Deserialize, Serialize};

mod authorize_impl;
pub use authorize_impl::*;

mod authorize_error;
pub use authorize_error::*;

mod nft_authorize;
mod web3_authorize;

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

    fn check_signature(&self) -> Result<(), AuthorizeError>;

    async fn authorize(&self) -> Result<(), AuthorizeError> {
        self.check_account()?;
        self.check_nonce()?;
        self.check_signature()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AuthScope {
    #[cfg(feature = "nft")]
    #[serde(rename = "nft")]
    NFT,
    #[serde(rename = "account")]
    Account,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AuthorizeOutcome {
    RedirectNeeded(String),
    Error(String),
    Success(AuthData),
    Denied(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthData {
    pub code: String,
    pub id_token: Option<String>,
}
