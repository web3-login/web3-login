use crate::traits::AuthorizeTrait;

pub struct AuthorizeImpl {
    pub config: crate::config::Config,
    pub claims: crate::claims::ClaimsMutex,
    pub tokens: crate::token::Tokens,
}

impl AuthorizeImpl {
    pub fn new(
        config: crate::config::Config,
        claims: crate::claims::ClaimsMutex,
        tokens: crate::token::Tokens,
    ) -> Self {
        Self {
            config,
            claims,
            tokens,
        }
    }
}

impl AuthorizeTrait for AuthorizeImpl {
    fn authorize(
        &self,
        realm: Option<String>,
        client_id: String,
        redirect_uri: String,
        state: Option<String>,
        response_type: Option<String>,
        response_mode: Option<String>,
        nonce: Option<String>,
        account: Option<String>,
        signature: Option<String>,
        chain_id: Option<String>,
        contract: Option<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        todo!()
    }
}
