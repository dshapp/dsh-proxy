//! Command line entry point: parse two flags, bind one port, serve.

use std::io::Result;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tokio::net::TcpListener;

use dsh_proxy::noise;

#[tokio::main]
async fn main() -> Result<()> {
    let mut listen = "0.0.0.0:443".to_string();
    let mut key: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next().unwrap_or(listen),
            "--key" => key = args.next(),
            "--help" | "-h" => {
                eprintln!("dsh-proxy [--listen HOST:PORT] [--key BASE64_X25519_PRIVATE]");
                return Ok(());
            }
            other => {
                eprintln!("dsh-proxy: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let private = match key {
        Some(text) => B64.decode(text.trim()).unwrap_or_else(|_| {
            eprintln!("dsh-proxy: --key is not base64");
            std::process::exit(2)
        }),
        None => noise::generate_keypair()?.0,
    };
    let public = noise::public_key_of(&private)?;

    let listener = TcpListener::bind(&listen).await?;
    eprintln!("dsh-proxy listening on {listen}");
    eprintln!("dsh-proxy public key {}", B64.encode(public));

    dsh_proxy::run(listener, Arc::new(private)).await
}
