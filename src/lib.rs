pub mod authorize;
pub mod claims;

#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
pub mod jwk;
pub mod token;
pub mod userinfo;
pub mod web3;

pub mod nft_owner;
pub mod signature_validator;
pub mod signing_key_store;

pub mod server;
pub mod traits;
pub mod well_known;

pub mod prelude {
    pub use crate::server::routes::oidc_routes;
    pub use crate::server::Server;
    pub use crate::traits::*;
}
