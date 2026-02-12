use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305,
};
use clap::Parser;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use x25519_dalek::x25519;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ip address of the server <ip:port>
    #[clap(short, long, value_parser)]
    ip_addr: String,

    /// path to app public key file
    #[arg(short, long)]
    app: String,

    /// path to private key file
    #[arg(short, long)]
    secret: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    println!("secret: {}, app: {}", cli.secret, cli.app);

    let mut file = File::open(cli.secret)?;
    let mut secret = [0u8; 32];
    file.read_exact(&mut secret)?;

    let mut file = File::open(cli.app)?;
    let mut app = [0u8; 32];
    file.read_exact(&mut app)?;

    let app_shared = x25519(secret, app);
    let app_cipher = ChaCha20Poly1305::new(&app_shared.into());

    let msg = [12, 43];
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let buf = app_cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &msg,
                aad: &[0],
            },
        )
        .unwrap();

    let outbound = TcpStream::connect(cli.ip_addr).await?;
    let (mut ro, mut wo) = tokio::io::split(outbound);
    wo.write_u8(0).await?;
    wo.write_all(nonce.as_slice()).await?;
    wo.write_all(buf.as_slice()).await?;
    wo.shutdown().await?;

    let mut resp = String::with_capacity(1000);
    ro.read_to_string(&mut resp).await?;

    println!("Repsonse: {}", resp);

    Ok(())
}