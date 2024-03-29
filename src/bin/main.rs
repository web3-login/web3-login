#[cfg(feature = "bin")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::TcpListener;

    #[cfg(feature = "cli")]
    use clap::Parser;
    #[cfg(feature = "cli")]
    use web3_login::cli::Args;
    use web3_login::config::load_yml_config as load_config;
    use web3_login::server::{router, Server};

    pretty_env_logger::try_init().ok();

    let (config, port) = {
        #[cfg(feature = "cli")]
        {
            let args = Args::parse();
            (load_config(args.config), args.port.unwrap_or(8080))
        }
        #[cfg(not(feature = "cli"))]
        {
            (load_config("config.yml".into()), 8080)
        }
    };

    let server = Server::new(config);

    let app = router(server)?;

    let addr_v4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);

    log::info!("Listening on {}", addr_v4);

    let listener = TcpListener::bind(addr_v4).await?;

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

#[cfg(not(feature = "bin"))]
fn main() {
    println!("This binary is not available without the `bin` feature.");
    println!("Please use `cargo run --features bin` instead.")
}
