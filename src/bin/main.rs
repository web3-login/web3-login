use std::net::{Ipv4Addr, SocketAddrV4};

use clap::Parser;
use web3_login::cli::Args;
use web3_login::config::load_yml_config as load_config;
use web3_login::server::{router, Server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::try_init().ok();

    let args = Args::parse();

    let config = load_config(args.config);

    let server = Server::new(config);

    let app = router(server)?;

    let port = args.port.unwrap_or(8080);

    let addr_v4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);

    log::info!("Listening on {}", addr_v4);

    let listener = tokio::net::TcpListener::bind(addr_v4).await?;

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
