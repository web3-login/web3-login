use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Deserialize)]
pub struct Config {
    pub ext_hostname: String,
    pub key_id: String,
    pub node_provider: HashMap<String, String>,
    pub chain_id: HashMap<String, i32>,
    pub rsa_pem: Option<String>,
}

pub fn realms(config: &Config) -> Vec<String> {
    config
        .node_provider
        .keys()
        .map(|f| f.clone())
        .collect::<Vec<String>>()
}
