use super::Authorize;
use async_trait::async_trait;

pub struct Web3Authorize {
    pub account: Option<String>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
}

#[cfg_attr(not(feature = "wasm"), async_trait)]
#[cfg_attr(feature="wasm", async_trait(?Send))]
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
