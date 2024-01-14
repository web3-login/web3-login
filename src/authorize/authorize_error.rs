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
