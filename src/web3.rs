use futures::executor::block_on;
use std::str::FromStr;
use web3::signing::{keccak256, recover};
use web3::{
    contract::{Contract, Error, Options},
    types::{Address, U256},
};

use crate::nft_owner::NFTOwner;
use crate::signature_validator::SignatureValidator;

pub struct Web3 {}

impl SignatureValidator for Web3 {
    fn validate_signature(&self, account: String, nonce: String, signature: String) -> bool {
        validate_signature(account, nonce, signature)
    }
}

impl NFTOwner for Web3 {
    fn is_nft_owner(
        &self,
        contract: String,
        account: String,
        _nft: Option<String>,
        chain: String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(block_on(is_nft_owner_of(contract, account, chain))?)
    }
}

pub fn validate_signature(account: String, nonce: String, signature: String) -> bool {
    let message = eth_message(format!("{};{}", account, nonce));
    if signature.len() < 2 {
        return false;
    }
    let signature = (signature[2..]).to_string();
    let signature = hex::decode(signature);
    if signature.is_err() {
        return false;
    }
    let signature = signature.unwrap();
    let recovery_id = signature[64] as i32 - 27;
    let pubkey = recover(&message, &signature[..64], recovery_id);
    let pubkey = format!("{:02X?}", pubkey.unwrap());
    pubkey == account
}

pub async fn is_nft_owner_of(
    contract_address: String,
    owner_address: String,
    node_provider: String,
) -> web3::Result<bool> {
    let transport = web3::transports::Http::new(&node_provider).unwrap();
    let web3 = web3::Web3::new(transport);
    let abi = include_bytes!("erc721.json");

    let contract_address = match Address::from_str(&contract_address) {
        Ok(address) => address,
        Err(e) => return Err(web3::Error::InvalidResponse(e.to_string())),
    };
    let contract = Contract::from_json(web3.eth(), contract_address, abi).unwrap();

    let owner_address = Address::from_str(&owner_address).unwrap();
    let balance: Result<U256, Error> = contract
        .query(
            "balanceOf",
            (owner_address,),
            None,
            Options::default(),
            None,
        )
        .await;
    match balance {
        Ok(balance) => Ok(balance > U256::from(0)),
        Err(e) => Err(web3::Error::InvalidResponse(e.to_string())),
    }
}

pub fn eth_message(message: String) -> [u8; 32] {
    keccak256(
        format!(
            "{}{}{}",
            "\x19Ethereum Signed Message:\n",
            message.len(),
            message
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use web3::signing::{keccak256, recover};

    pub fn eth_message(message: String) -> [u8; 32] {
        keccak256(
            format!(
                "{}{}{}",
                "\x19Ethereum Signed Message:\n",
                message.len(),
                message
            )
            .as_bytes(),
        )
    }

    #[test]
    fn test_wrong_signature() {
        let account = "".to_string();
        let nonce = "".to_string();
        let signature = "".to_string();
        assert!(!validate_signature(
            account.clone(),
            nonce.clone(),
            signature
        ));

        let signature = "foobar".to_string();
        assert!(!validate_signature(account, nonce, signature));
    }

    #[test]
    fn test_recover() {
        let account = "0x63f9a92d8d61b48a9fff8d58080425a3012d05c8".to_string();
        let message = "0x63f9a92d8d61b48a9fff8d58080425a3012d05c8igwyk4r1o7o".to_string();
        let message = eth_message(message);
        let signature = hex::decode("382a3e04daf88f322730f6a2972475fc5646ea8c4a7f3b5e83a90b10ba08a7364cd2f55348f2b6d210fbed7fc485abf19ecb2f3967e410d6349dd7dd1d4487751b").unwrap();
        println!("{} {:?} {:?}", account, message, signature);
        let recovery_id = signature[64] as i32 - 27;
        let pubkey = recover(&message, &signature[..64], recovery_id);
        assert!(pubkey.is_ok());
        let pubkey = pubkey.unwrap();
        let pubkey = format!("{:02X?}", pubkey);
        assert_eq!(account, pubkey)
    }

    #[test]
    fn test_validate() {
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        assert!(validate_signature(account, nonce, signature));
    }

    #[tokio::test]
    async fn test_crypto_boy_on_okt() {
        let node_provider = "https://exchaintestrpc.okex.org".to_string();

        let nft_addr = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4".to_string();
        let owner = "0x9c9E8eAbD947658bDb713E0d3eBfe56860abdb8D".to_string();
        assert!(is_nft_owner_of(nft_addr, owner, node_provider)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_crypto_boy_on_okt_lower_case() {
        let node_provider = "https://exchaintestrpc.okex.org".to_string();

        let nft_addr = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4".to_string();
        let owner = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        assert!(is_nft_owner_of(nft_addr, owner, node_provider)
            .await
            .unwrap());
    }

    #[test]
    fn test_validate_signature() {
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let web3 = Web3 {};
        assert!(web3.validate_signature(account, nonce, signature));
    }

    #[test]
    fn test_validate_signature_2() {
        let account = "0x9c9E8eAbD947658bDb713E0d3eBfe56860abdb8D".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let web3 = Web3 {};
        assert!(!web3.validate_signature(account, nonce, signature));
    }
}
