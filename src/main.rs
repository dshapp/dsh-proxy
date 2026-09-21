//! Command line entry point: parse a few flags, bind one port, serve.

use std::io::Result;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dashmap::DashMap;
use tokio::net::TcpListener;

use dsh_proxy::edge::Edge;
use dsh_proxy::phone::Pool;
use dsh_proxy::state::Registry;
use dsh_proxy::{noise, tls, Limits, Table};

#[tokio::main]
async fn main() -> Result<()> {
    let mut listen = "0.0.0.0:443".to_string();
    let mut key: Option<String> = None;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut state: Option<String> = None;
    let mut self_signed = false;
    let mut tunnels_per_device: usize = 8;
    let mut limits = Limits::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next().unwrap_or(listen),
            "--key" => key = args.next(),
            "--tls-cert" => tls_cert = args.next(),
            "--tls-key" => tls_key = args.next(),
            "--tls-self-signed" => self_signed = true,
            "--state" => state = args.next(),
            "--max-tunnels-per-device" => {
                tunnels_per_device = positive(&mut args, "--max-tunnels-per-device")
            }
            "--max-bridges" => limits.max_bridges = positive(&mut args, "--max-bridges"),
            "--max-clients-per-ip" => {
                limits.max_clients_per_ip = positive(&mut args, "--max-clients-per-ip")
            }
            "--max-bridges-per-ip" => {
                limits.max_bridges_per_ip = positive(&mut args, "--max-bridges-per-ip")
            }
            "--max-streams-per-bridge" => {
                limits.max_streams_per_bridge = positive(&mut args, "--max-streams-per-bridge")
            }
            "--handshake-timeout-ms" => {
                limits.handshake_timeout =
                    Duration::from_millis(positive(&mut args, "--handshake-timeout-ms") as u64)
            }
            "--help" | "-h" => {
                eprintln!(
                    "dsh-proxy [--listen HOST:PORT] [--key BASE64_X25519_PRIVATE]\n\
                     \t[--tls-cert PEM] [--tls-key PEM] [--tls-self-signed]\n\
                     \t[--state FILE] [--max-tunnels-per-device N]\n\
                     \t[--max-bridges N] [--max-bridges-per-ip N]\n\
                     \t[--max-streams-per-bridge N] [--handshake-timeout-ms N]\n\
                     \t[--max-clients-per-ip N]"
                );
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

    // TLS is what every client sees now, so there is no unencrypted mode: a
    // real certificate, or an explicit self-signed one for development.
    let identity = match (tls_cert.as_deref(), tls_key.as_deref()) {
        (Some(cert), Some(key)) => tls::load_pem(cert, key)?,
        (None, None) if self_signed => tls::self_signed(&["localhost"])?,
        _ => {
            eprintln!("dsh-proxy: provide --tls-cert and --tls-key, or --tls-self-signed");
            std::process::exit(2)
        }
    };
    let tls = tls::server_config(identity)?;

    let table: Table = Arc::new(DashMap::new());
    let registry = Arc::new(Registry::open(state)?);
    let pool = Arc::new(Pool::new(table.clone(), tunnels_per_device));
    let edge = Arc::new(Edge { pool, registry, tls, table });

    let listener = TcpListener::bind(&listen).await?;
    eprintln!("dsh-proxy listening on {listen}");
    eprintln!("dsh-proxy public key {}", B64.encode(public));

    dsh_proxy::run_edge(listener, Arc::new(private), limits, edge).await
}

/// Read the next argument as a positive integer, or exit with a usage error.
fn positive(args: &mut impl Iterator<Item = String>, flag: &str) -> usize {
    match args.next().map(|value| value.parse::<usize>()) {
        Some(Ok(value)) if value > 0 => value,
        _ => {
            eprintln!("dsh-proxy: {flag} needs a positive integer");
            std::process::exit(2);
        }
    }
}
