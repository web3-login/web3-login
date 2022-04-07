use crate::{
    config::{get_node, Config},
    web3::{is_nft_owner_of, validate_signature},
};
use async_trait::async_trait;
use std::fmt;

#[derive(Debug, Clone)]
pub enum AuthorizeError {
    AccountError,
    NonceError,
    SignatureError,
    NFTError,
}

impl std::error::Error for AuthorizeError {}

impl fmt::Display for AuthorizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthorizeError::AccountError => write!(f, "Account Error"),
            AuthorizeError::NonceError => write!(f, "Nonce Error"),
            AuthorizeError::SignatureError => write!(f, "Signature Error"),
            AuthorizeError::NFTError => write!(f, "NFT Error"),
        }
    }
}

#[async_trait]
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

pub struct Web3Authorize {
    pub account: Option<String>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
}

#[async_trait]
impl Authorize for Web3Authorize {
    fn get_account(&self) -> &Option<String> {
        &self.account
    }
    fn get_nonce(&self) -> &Option<String> {
        &self.nonce
    }
    fn get_signature(&self) -> &Option<String> {
        &self.signature
    }
}

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

#[async_trait]
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

    async fn authorize(&self) -> Result<(), AuthorizeError> {
        self.check_account()?;
        self.check_nonce()?;
        self.check_signature()?;
        self.check_nft().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce() {
        let params = Web3Authorize {
            account: None,
            nonce: Some("some_nonce".to_string()),
            signature: None,
        };
        assert!(params.check_nonce().is_ok());

        let params = Web3Authorize {
            account: None,
            nonce: None,
            signature: None,
        };
        assert!(params.check_nonce().is_err());
    }

    #[test]
    fn test_signature() {
        let params = Web3Authorize {
            account: Some("0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string()),
            nonce: Some("dotzxrenodo".to_string()),
            signature: Some("0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string()),
        };
        assert!(params.check_signature().is_ok());

        let params = Web3Authorize {
            account: None,
            nonce: None,
            signature: None,
        };
        assert!(params.check_signature().is_err());
    }
}
