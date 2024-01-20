#![cfg(feature = "nft")]

use crate::web3::is_nft_owner_of;
use crate::web3::validate_signature;
use async_trait::async_trait;

use super::Authorize;
use super::AuthorizeError;

pub struct NFTAuthorize {
    pub account: Option<String>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
    pub node: String,
    pub realm: String,
    pub contract: String,
}

impl NFTAuthorize {
    async fn check_nft(&self) -> Result<(), AuthorizeError> {
        let is_owner = is_nft_owner_of(
            self.contract.to_string(),
            self.account.clone().unwrap().to_string(),
            self.node.clone(),
        )
        .await;
        match is_owner {
            Ok(true) => Ok(()),
            _ => Err(AuthorizeError::NFTError),
        }
    }
}

#[cfg_attr(not(feature = "wasm"), async_trait)]
#[cfg_attr(feature="wasm", async_trait(?Send))]
impl Authorize for NFTAuthorize {
    fn get_account(&self) -> &Option<String> {
        &self.account
    }
    fn get_nonce(&self) -> &Option<String> {
        &self.nonce
    }
    fn get_signature(&self) -> &Option<String> {
        &self.signature
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
        self.check_nft().await?;
        Ok(())
    }
}
