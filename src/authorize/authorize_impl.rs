use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    claims::{additional_claims, standard_claims},
    config::{get_chain_id, get_node},
    token::token,
    traits::AuthorizeTrait,
};
use openidconnect::TokenResponse;
use openidconnect::{AccessToken, AuthorizationCode};
use url::Url;
use uuid::Uuid;

use super::{AuthScope, Authorize, AuthorizeError, AuthorizeOutcome};

#[cfg(feature = "account")]
use super::web3_authorize::Web3Authorize;

#[cfg(feature = "nft")]
use super::nft_authorize::NFTAuthorize;

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

    pub fn new_with_config(config: crate::config::Config) -> Self {
        let claims: crate::claims::ClaimsMutex = crate::claims::ClaimsMutex {
            standard_claims: Arc::new(Mutex::new(HashMap::new())),
            additional_claims: Arc::new(Mutex::new(HashMap::new())),
        };

        let tokens: crate::token::Tokens = crate::token::Tokens {
            muted: Arc::new(Mutex::new(HashMap::new())),
            bearer: Arc::new(Mutex::new(HashMap::new())),
        };

        Self {
            config,
            claims,
            tokens,
        }
    }
}

#[async_trait::async_trait]
impl AuthorizeTrait for AuthorizeImpl {
    async fn authorize(
        &self,
        #[allow(unused_variables)] auth_scope: AuthScope,
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
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> Result<AuthorizeOutcome, Box<dyn std::error::Error>> {
        #[cfg(feature = "nft")]
        if auth_scope == AuthScope::NFT {
            return self
                .authorize_nft(
                    realm.unwrap_or_else(|| "default".into()),
                    client_id,
                    redirect_uri,
                    state,
                    response_type,
                    response_mode,
                    nonce,
                    account,
                    signature,
                    chain_id,
                    contract,
                    code_challenge,
                    code_challenge_method,
                )
                .await;
        }

        match contract {
            #[cfg(feature = "nft")]
            Some(contract) => {
                self.authorize_nft(
                    realm.unwrap_or_else(|| "default".into()),
                    client_id,
                    redirect_uri,
                    state,
                    response_type,
                    response_mode,
                    nonce,
                    account,
                    signature,
                    chain_id,
                    Some(contract),
                    code_challenge,
                    code_challenge_method,
                )
                .await
            }

            _ => {
                #[cfg(feature = "account")]
                {
                    self.authorize_account(
                        realm.unwrap_or_else(|| "default".into()),
                        client_id,
                        redirect_uri,
                        state,
                        response_type,
                        response_mode,
                        nonce,
                        account,
                        signature,
                        chain_id,
                        contract,
                        code_challenge,
                        code_challenge_method,
                    )
                    .await
                }
                #[cfg(not(feature = "account"))]
                Ok(AuthorizeOutcome::Denied("access%20denied".to_string()))
            }
        }
    }
}

impl AuthorizeImpl {
    #[cfg(feature = "account")]
    async fn authorize_account(
        &self,
        realm: String,
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
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> Result<AuthorizeOutcome, Box<dyn std::error::Error>> {
        if Url::parse(&redirect_uri).is_err() {
            return Ok(AuthorizeOutcome::Error(
                "wrong%20redirect%20uri".to_string(),
            ));
        }

        if account.is_none() {
            let mut url = Url::parse(&format!("{}/", self.config.frontend_host)).unwrap();
            url.query_pairs_mut()
                .clear()
                .append_pair("client_id", &client_id)
                .append_pair("state", &state.unwrap_or_default())
                .append_pair("nonce", &nonce.unwrap_or_default())
                .append_pair("response_type", &response_type.unwrap_or_default())
                .append_pair("response_mode", &response_mode.unwrap_or_default())
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("realm", &realm.clone())
                .append_pair(
                    "chain_id",
                    &chain_id.clone().unwrap_or_else(|| realm.clone()),
                )
                .append_pair("contract", &contract.unwrap_or_else(|| client_id.clone()));
            if let Some(code_challenge) = code_challenge {
                url.query_pairs_mut()
                    .append_pair("code_challenge", &code_challenge);
            }
            if let Some(code_challenge_method) = code_challenge_method {
                url.query_pairs_mut()
                    .append_pair("code_challenge_method", &code_challenge_method);
            }
            return Ok(AuthorizeOutcome::RedirectNeeded(url.to_string()));
        };

        let realm_or_chain_id = match realm.as_str() {
            "default" => chain_id.clone().unwrap_or_else(|| "default".into()),
            _ => realm.clone(),
        };

        let node_provider = get_node(&self.config, &realm_or_chain_id);

        let authorize = Web3Authorize {
            account: account.clone(),
            nonce: nonce.clone(),
            signature: signature.clone(),
        };

        match authorize.authorize().await {
            Ok(_) => (),
            Err(err) => match err {
                AuthorizeError::AccountError => {
                    return Ok(AuthorizeOutcome::Error("account%20missing".to_string()))
                }
                AuthorizeError::NonceError => {
                    return Ok(AuthorizeOutcome::Error("nonce%20missing".to_string()))
                }
                AuthorizeError::SignatureError => {
                    return Ok(AuthorizeOutcome::Error("signature%20missing".to_string()))
                }
                AuthorizeError::NFTError => {
                    return Ok(AuthorizeOutcome::Denied("access%20denied".to_string()))
                }
            },
        };

        let redirect_uri = Url::parse(&redirect_uri);

        if redirect_uri.is_err() {
            return Ok(AuthorizeOutcome::Error(
                "wrong%20redirect%20uri".to_string(),
            ));
        }

        let mut redirect_uri = redirect_uri.unwrap();

        let access_token = AccessToken::new(Uuid::new_v4().to_string());
        let code = AuthorizationCode::new(Uuid::new_v4().to_string());
        let chain_id = get_chain_id(&self.config, &realm_or_chain_id);

        let standard_claims = standard_claims(&account.clone().unwrap());

        let node_provider_url = Url::parse(&node_provider).unwrap();
        let node_provider_host = node_provider_url.host().unwrap().to_string();

        let additional_claims = additional_claims(
            &account.unwrap(),
            &nonce.clone().unwrap(),
            &signature.unwrap(),
            &chain_id,
            &node_provider_host,
            "",
        );

        self.claims
            .standard_claims
            .try_lock()
            .unwrap()
            .insert(access_token.secret().clone(), standard_claims.clone());
        self.claims
            .additional_claims
            .try_lock()
            .unwrap()
            .insert(access_token.secret().clone(), additional_claims.clone());

        let token = token(
            &self.config,
            client_id,
            nonce,
            standard_claims,
            additional_claims,
            access_token.clone(),
            code.clone(),
        );

        let id_token = token.id_token().unwrap().to_string();

        self.tokens
            .bearer
            .try_lock()
            .unwrap()
            .insert(code.secret().clone(), access_token.secret().clone());
        self.tokens
            .muted
            .try_lock()
            .unwrap()
            .insert(access_token.secret().clone(), token);

        if let Some(response_type) = response_type {
            if response_type.contains("code") {
                redirect_uri
                    .query_pairs_mut()
                    .append_pair("code", code.secret());
            }
            if response_type.contains("id_token") || response_type.contains("token") {
                redirect_uri
                    .query_pairs_mut()
                    .append_pair("id_token", &id_token);
            }
        } else {
            redirect_uri
                .query_pairs_mut()
                .append_pair("code", code.secret());
        };

        if let Some(state) = state {
            redirect_uri.query_pairs_mut().append_pair("state", &state);
        };

        Ok(AuthorizeOutcome::RedirectNeeded(redirect_uri.to_string()))
    }

    #[cfg(feature = "nft")]
    async fn authorize_nft(
        &self,
        realm: String,
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
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> Result<AuthorizeOutcome, Box<dyn std::error::Error>> {
        if Url::parse(&redirect_uri).is_err() {
            return Ok(AuthorizeOutcome::Error(
                "wrong%20redirect%20uri".to_string(),
            ));
        }

        if account.is_none() {
            let mut url = Url::parse(&format!("{}/", self.config.frontend_host)).unwrap();
            url.query_pairs_mut()
                .clear()
                .append_pair("client_id", &client_id)
                .append_pair("state", &state.unwrap_or_default())
                .append_pair("nonce", &nonce.unwrap_or_default())
                .append_pair("response_type", &response_type.unwrap_or_default())
                .append_pair("response_mode", &response_mode.unwrap_or_default())
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("realm", &realm.clone())
                .append_pair(
                    "chain_id",
                    &chain_id.clone().unwrap_or_else(|| realm.clone()),
                )
                .append_pair("contract", &contract.unwrap_or_else(|| client_id.clone()));
            if let Some(code_challenge) = code_challenge {
                url.query_pairs_mut()
                    .append_pair("code_challenge", &code_challenge);
            }
            if let Some(code_challenge_method) = code_challenge_method {
                url.query_pairs_mut()
                    .append_pair("code_challenge_method", &code_challenge_method);
            }
            return Ok(AuthorizeOutcome::RedirectNeeded(url.to_string()));
        };

        let contract = contract.unwrap_or_else(|| client_id.clone());

        let realm_or_chain_id = match realm.as_str() {
            "default" => chain_id.clone().unwrap_or_else(|| "default".into()),
            _ => realm.clone(),
        };

        let node_provider = get_node(&self.config, &realm_or_chain_id);

        let authorize = NFTAuthorize {
            account: account.clone(),
            nonce: nonce.clone(),
            signature: signature.clone(),
            node: node_provider.clone(),
            realm: realm_or_chain_id.clone(),
            contract: contract.clone(),
        };

        match authorize.authorize().await {
            Ok(_) => (),
            Err(err) => match err {
                AuthorizeError::AccountError => {
                    return Ok(AuthorizeOutcome::Error("account%20missing".to_string()))
                }
                AuthorizeError::NonceError => {
                    return Ok(AuthorizeOutcome::Error("nonce%20missing".to_string()))
                }
                AuthorizeError::SignatureError => {
                    return Ok(AuthorizeOutcome::Error("signature%20missing".to_string()))
                }
                AuthorizeError::NFTError => {
                    return Ok(AuthorizeOutcome::Denied("access%20denied".to_string()))
                }
            },
        };

        let redirect_uri = Url::parse(&redirect_uri);

        if redirect_uri.is_err() {
            return Ok(AuthorizeOutcome::Error(
                "wrong%20redirect%20uri".to_string(),
            ));
        }

        let mut redirect_uri = redirect_uri.unwrap();

        let access_token = AccessToken::new(Uuid::new_v4().to_string());
        let code = AuthorizationCode::new(Uuid::new_v4().to_string());
        let chain_id = get_chain_id(&self.config, &realm_or_chain_id);

        let standard_claims = standard_claims(&account.clone().unwrap());

        let node_provider_url = Url::parse(&node_provider).unwrap();
        let node_provider_host = node_provider_url.host().unwrap().to_string();

        let additional_claims = additional_claims(
            &account.unwrap(),
            &nonce.clone().unwrap(),
            &signature.unwrap(),
            &chain_id,
            &node_provider_host,
            &contract,
        );

        self.claims
            .standard_claims
            .try_lock()
            .unwrap()
            .insert(access_token.secret().clone(), standard_claims.clone());

        self.claims
            .additional_claims
            .try_lock()
            .unwrap()
            .insert(access_token.secret().clone(), additional_claims.clone());

        let token = token(
            &self.config,
            client_id,
            nonce,
            standard_claims,
            additional_claims,
            access_token.clone(),
            code.clone(),
        );

        let id_token = token.id_token().unwrap().to_string();

        self.tokens
            .bearer
            .try_lock()
            .unwrap()
            .insert(code.secret().clone(), access_token.secret().clone());
        self.tokens
            .muted
            .try_lock()
            .unwrap()
            .insert(access_token.secret().clone(), token);

        if let Some(response_type) = response_type {
            if response_type.contains("code") {
                redirect_uri
                    .query_pairs_mut()
                    .append_pair("code", code.secret());
            }
            if response_type.contains("id_token") || response_type.contains("token") {
                redirect_uri
                    .query_pairs_mut()
                    .append_pair("id_token", &id_token);
            }
        } else {
            redirect_uri
                .query_pairs_mut()
                .append_pair("code", code.secret());
        };

        if let Some(state) = state {
            redirect_uri.query_pairs_mut().append_pair("state", &state);
        };

        Ok(AuthorizeOutcome::RedirectNeeded(redirect_uri.to_string()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_redirect_parameters() {
        let config = crate::config::tests::test_config();
        let authorize = AuthorizeImpl::new_with_config(config.clone());

        let realm = Some("default".to_string());
        let client_id = "client_id".to_string();
        let redirect_uri = "https://redirect_uri".to_string();
        let state = Some("state".to_string());
        let response_type = Some("response_type".to_string());
        let response_mode = Some("response_mode".to_string());
        let nonce = Some("nonce".to_string());
        let account = None;
        let signature = Some("signature".to_string());
        let chain_id = Some("chain_id".to_string());
        let contract = Some("contract".to_string());
        let code_challenge = Some("code_challenge".to_string());
        let code_challenge_method = Some("code_challenge_method".to_string());

        let outcome = authorize
            .authorize(
                AuthScope::Account,
                realm,
                client_id,
                redirect_uri,
                state,
                response_type,
                response_mode,
                nonce,
                account,
                signature,
                chain_id,
                contract,
                code_challenge,
                code_challenge_method,
            )
            .await;

        assert!(outcome.is_ok());

        let outcome = outcome.unwrap();

        assert!(matches!(outcome, AuthorizeOutcome::RedirectNeeded(_)));

        let outcome = match outcome {
            AuthorizeOutcome::RedirectNeeded(outcome) => outcome,
            _ => "".to_string(),
        };

        let url = Url::parse(&outcome);

        assert!(url.is_ok());

        let url = url.unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.path(), "/");

        let query_pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(query_pairs.get("client_id"), Some(&"client_id".to_string()));
        assert_eq!(query_pairs.get("state"), Some(&"state".to_string()));
        assert_eq!(query_pairs.get("nonce"), Some(&"nonce".to_string()));
        assert_eq!(
            query_pairs.get("response_type"),
            Some(&"response_type".to_string())
        );
        assert_eq!(
            query_pairs.get("response_mode"),
            Some(&"response_mode".to_string())
        );
        assert_eq!(
            query_pairs.get("redirect_uri"),
            Some(&"https://redirect_uri".to_string())
        );
        assert_eq!(query_pairs.get("realm"), Some(&"default".to_string()));
        assert_eq!(query_pairs.get("chain_id"), Some(&"chain_id".to_string()));
        assert_eq!(query_pairs.get("contract"), Some(&"contract".to_string()));
        assert_eq!(
            query_pairs.get("code_challenge"),
            Some(&"code_challenge".to_string())
        );
        assert_eq!(
            query_pairs.get("code_challenge_method"),
            Some(&"code_challenge_method".to_string())
        );
    }
}
