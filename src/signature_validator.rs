pub trait SignatureValidator {
    fn validate_signature(&self, account: String, nonce: String, signature: String) -> bool;
}
