use openidconnect::{
    core::{
        CoreClaimName, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, ResponseTypes, Scope,
    TokenUrl, UserInfoUrl,
};

use crate::{authorize::AuthScope, config::Config, traits::WellKnownTrait};

pub struct WellKnownImpl {
    config: Config,
}

impl WellKnownImpl {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

impl WellKnownTrait for WellKnownImpl {
    fn openid_configuration(
        &self,
        auth_scope: AuthScope,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let provider_metadata = CoreProviderMetadata::new(
            IssuerUrl::new(match auth_scope {
                AuthScope::Account => format!("{}", self.config.ext_hostname),
                #[cfg(feature = "nft")]
                AuthScope::NFT => format!("{}/nft", self.config.ext_hostname),
            })?,
            AuthUrl::new(match auth_scope {
                AuthScope::Account => format!("{}/authorize", self.config.ext_hostname),
                #[cfg(feature = "nft")]
                AuthScope::NFT => format!("{}/nft/authorize", self.config.ext_hostname),
            })?,
            JsonWebKeySetUrl::new(match auth_scope {
                AuthScope::Account => format!("{}/jwk", self.config.ext_hostname),
                #[cfg(feature = "nft")]
                AuthScope::NFT => format!("{}/nft/jwk", self.config.ext_hostname),
            })?,
            vec![
                ResponseTypes::new(vec![CoreResponseType::Code]),
                ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
            ],
            vec![CoreSubjectIdentifierType::Pairwise],
            vec![
                CoreJwsSigningAlgorithm::EdDsaEd25519,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            ],
            EmptyAdditionalProviderMetadata {},
        )
        .set_token_endpoint(Some(TokenUrl::new(match auth_scope {
            AuthScope::Account => format!("{}/token", self.config.ext_hostname),
            #[cfg(feature = "nft")]
            AuthScope::NFT => format!("{}/nft/token", self.config.ext_hostname),
        })?))
        .set_userinfo_endpoint(Some(UserInfoUrl::new(match auth_scope {
            AuthScope::Account => format!("{}/userinfo", self.config.ext_hostname),
            #[cfg(feature = "nft")]
            AuthScope::NFT => format!("{}/nft/userinfo", self.config.ext_hostname),
        })?))
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

    fn authorize_configuration(
        &self,
        auth_scope: AuthScope,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.openid_configuration(auth_scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openid_configuration() {
        let config: Config = Config::default();
        let well_known = WellKnownImpl::new(config);
        let openid_configuration = well_known.openid_configuration(AuthScope::Account).unwrap();
        assert_eq!(
            openid_configuration["issuer"],
            "http://localhost:8000".to_string()
        );
        assert_eq!(
            openid_configuration["authorization_endpoint"],
            "http://localhost:8000/authorize".to_string()
        );
        assert_eq!(
            openid_configuration["jwks_uri"],
            "http://localhost:8000/jwk".to_string()
        );
        assert_eq!(
            openid_configuration["token_endpoint"],
            "http://localhost:8000/token".to_string()
        );
        assert_eq!(
            openid_configuration["userinfo_endpoint"],
            "http://localhost:8000/userinfo".to_string()
        );
    }
}
