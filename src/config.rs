use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Deserialize)]
pub struct Config {
    pub ext_hostname: String,
    pub frontend_host: String,
    pub key_id: String,
    pub node_provider: HashMap<String, String>,
    pub chain_id: HashMap<String, i32>,
    pub rsa_pem: Option<String>,
}

pub fn realms(config: &Config) -> Vec<String> {
    config
        .node_provider
        .keys()
        .cloned()
        .collect::<Vec<String>>()
}

pub fn get_chain_id(config: &Config, realm: &str) -> i32 {
    let numeric = realm.parse::<i32>();
    match numeric {
        Ok(ok) => match config.chain_id.values().any(|&val| val == ok) {
            true => ok,
            false => 42,
        },
        Err(_) => *config.chain_id.get(realm).unwrap_or(&42),
    }
}

pub fn get_node(config: &Config, realm: &str) -> String {
    let chain_id = get_chain_id(config, realm);

    let node = config
        .chain_id
        .iter()
        .find_map(|(key, &val)| if val == chain_id { Some(key) } else { None });

    match node {
        Some(node) => config.node_provider.get(node).unwrap().clone(),
        _ => config
            .node_provider
            .get(&"default".to_string())
            .unwrap()
            .clone(),
    }
}
