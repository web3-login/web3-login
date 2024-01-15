use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Default, PartialEq, Deserialize, Clone)]
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

pub fn load_yml_config(path: PathBuf) -> Config {
    let config = std::fs::read_to_string(path).unwrap();
    serde_yaml::from_str(&config).unwrap()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_load_config_yml() {
        let config = load_yml_config(PathBuf::from("config.yml"));
        assert!(config.node_provider.len() > 2);
        assert!(config.chain_id.len() > 2);
    }
}
