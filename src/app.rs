use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use clap::Parser;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use x25519_dalek::x25519;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ip address of the server <ip:port>
    #[clap(short, long, value_parser)]
    ip_addr: String,

    /// path to private key file
    #[arg(short, long)]
    secret: String,

    /// path to loader public key file
    #[arg(short, long)]
    loader: String,

    /// path to requester public key file
    #[arg(short, long)]
    requester: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    println!(
        "secret: {}, loader: {}, requester: {}",
        cli.secret, cli.loader, cli.requester
    );

    let mut file = File::open(cli.secret)?;
    let mut secret = [0u8; 32];
    file.read_exact(&mut secret)?;

    let mut file = File::open(cli.loader)?;
    let mut loader = [0; 32];
    file.read_exact(&mut loader)?;

    let mut file = File::open(cli.requester)?;
    let mut requester = [0; 32];
    file.read_exact(&mut requester)?;

    let loader_shared = x25519(secret, loader);
    let loader_cipher = ChaCha20Poly1305::new(&loader_shared.into());

    println!("Listening on: {}", cli.ip_addr);

    let listener = TcpListener::bind(cli.ip_addr).await?;

    let mut data: Vec<u8> = vec![0, 0];
    while let Ok((inbound, _)) = listener.accept().await {
        let mut buf: Vec<u8> = Vec::with_capacity(1000);
        let (mut ri, mut wi) = tokio::io::split(inbound);
        let len = ri.read_to_end(&mut buf).await?;

        if buf[0] == 0 {
            data = loader_cipher
                .decrypt(
                    buf[1..13].into(),
                    Payload {
                        msg: &buf[13..len],
                        aad: &[0],
                    },
                )
                .map_err(|e| "Decrypt failed: ".to_owned() + &e.to_string())?;
            wi.write_all(b"Data write suceeded!").await?;
        } else if buf[0] == 1 {
            let sum = data[0] + data[1];
            wi.write_all(b"Result: ").await?;
            wi.write_all(sum.to_string().as_bytes()).await?;
        } else {
            wi.write_all(b"Unknown msg").await?;
        }
    }

    Ok(())
}