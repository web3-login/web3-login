use openidconnect::{
    core::{
        CoreClaimName, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, ResponseTypes, Scope,
    TokenUrl, UserInfoUrl,
};

use crate::{config::Config, traits::WellKnownTrait};

pub struct WellKnownImpl {
    config: Config,
}

impl WellKnownImpl {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

impl WellKnownTrait for WellKnownImpl {
    fn openid_configuration(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let provider_metadata = CoreProviderMetadata::new(
            IssuerUrl::new(self.config.ext_hostname.to_string())?,
            AuthUrl::new(format!("{}/authorize", self.config.ext_hostname)).unwrap(),
            JsonWebKeySetUrl::new(format!("{}/jwk", self.config.ext_hostname)).unwrap(),
            vec![
                ResponseTypes::new(vec![CoreResponseType::Code]),
                ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
            ],
            vec![CoreSubjectIdentifierType::Pairwise],
            vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
            EmptyAdditionalProviderMetadata {},
        )
        .set_token_endpoint(Some(TokenUrl::new(format!(
            "{}/token",
            self.config.ext_hostname
        ))?))
        .set_userinfo_endpoint(Some(UserInfoUrl::new(format!(
            "{}/userinfo",
            self.config.ext_hostname
        ))?))
        .set_scopes_supported(Some(vec![
            Scope::new("openid".to_string()),
            Scope::new("nft".to_string()),
        ]))
        .set_claims_supported(Some(vec![
            CoreClaimName::new("sub".to_string()),
            CoreClaimName::new("aud".to_string()),
            CoreClaimName::new("exp".to_string()),
            CoreClaimName::new("iat".to_string()),
            CoreClaimName::new("iss".to_string()),
            CoreClaimName::new("name".to_string()),
        ]));
        Ok(serde_json::to_value(provider_metadata)?)
    }

    fn authorize_configuration(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.openid_configuration()
    }
}
