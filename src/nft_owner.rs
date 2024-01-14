pub trait NFTOwner {
    fn is_nft_owner(
        &self,
        contract: String,
        account: String,
        nft: Option<String>,
        chain: String,
    ) -> Result<bool, Box<dyn std::error::Error>>;
}
