use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, PartialEq, Deserialize, Clone)]
pub struct Config {
    pub ext_hostname: String,
    pub frontend_host: String,
    pub key_id: String,
    pub node_provider: HashMap<String, String>,
    pub chain_id: HashMap<String, i32>,
    pub eddsa_pem: Option<String>,
    pub rsa_pem: Option<String>,
    pub rsa_pem_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        let mut node_provider = HashMap::new();
        node_provider.insert(
            "default".to_string(),
            "https://kovan.infura.io/v3/43".to_string(),
        );
        let mut chain_id = HashMap::new();
        chain_id.insert("default".to_string(), 42);
        Config {
            ext_hostname: "http://localhost:8000".to_string(),
            frontend_host: "http://localhost:3000".to_string(),
            key_id: "default".to_string(),
            node_provider,
            chain_id,
            eddsa_pem: None,
            rsa_pem: None,
            rsa_pem_file: None,
        }
    }
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

    #[test]
    fn test_get_chain_id() {
        let config = Config::default();
        assert_eq!(get_chain_id(&config, "default"), 42);
        assert_eq!(get_chain_id(&config, "unknown"), 42);
    }

    #[test]
    fn test_get_node() {
        let config = Config::default();
        assert_eq!(
            get_node(&config, "default"),
            "https://kovan.infura.io/v3/43".to_string()
        );
        assert_eq!(
            get_node(&config, "unknown"),
            "https://kovan.infura.io/v3/43".to_string()
        );
    }
}
