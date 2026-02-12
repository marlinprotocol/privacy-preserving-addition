# Privacy-Preserving Addition Server

A secure enclave-based server that performs encrypted computation using AWS Nitro Enclaves via [Marlin Oyster](https://docs.marlin.org/oyster/).

## Overview

This project demonstrates privacy-preserving computation where:
- Data is encrypted before being sent to the server
- Computation happens inside a hardware-isolated enclave (TEE)
- Only authorized clients with correct keys can interact with the enclave
- Attestation proves the code running is genuine

### Components

| Binary | Description |
|--------|-------------|
| `app` | Main server - receives encrypted data, stores values, computes sum |
| `loader` | Client - encrypts and sends data `[12, 43]` to the server |
| `requester` | Client - requests the sum of stored values |
| `verifier` | Validates enclave attestation and extracts public key |
| `keygen` | Generates X25519 key pairs |

## Prerequisites

### Fedora/RHEL

```bash
# Install musl toolchain for static linking
sudo dnf install musl-gcc musl-devel

# Install Perl modules (required for building OpenSSL from source)
sudo dnf install perl-FindBin perl-IPC-Cmd perl-File-Compare perl-File-Copy perl-Pod-Html perl-core

# Add Rust musl target
rustup target add x86_64-unknown-linux-musl
```

### Ubuntu/Debian

```bash
sudo apt install musl-tools musl-dev
rustup target add x86_64-unknown-linux-musl
```

## Building

```bash
# Build all binaries
cargo build --release --target x86_64-unknown-linux-musl

# Binaries will be at:
# target/x86_64-unknown-linux-musl/release/{app,loader,requester,verifier,keygen}
```

## Deploying to Marlin Oyster (AWS Nitro Enclave)

### 1. Build the Application

```bash
# Build all binaries with static linking
cargo build --release --target x86_64-unknown-linux-musl
```

### 2. Build and Push Docker Image to Docker Hub

```bash
# Login to Docker Hub (create account at https://hub.docker.com if needed)
docker login

# Build the Docker image
docker build -f Dockerfile -t YOUR_DOCKERHUB_USERNAME/privacy-preserving-addition:latest .

# Push to Docker Hub
docker push YOUR_DOCKERHUB_USERNAME/privacy-preserving-addition:latest
```

**Note:** Replace `YOUR_DOCKERHUB_USERNAME` with your actual Docker Hub username.

### 4. Create docker-compose.yml

Create a `docker-compose.yml` file for Marlin Oyster deployment:

```yaml
services:
  app:
    image: YOUR_DOCKERHUB_USERNAME/privacy-preserving-addition:latest
    network_mode: host
    restart: unless-stopped
    volumes:
      - /app/id.sec:/app/keys/id.sec:ro
    command: ["--ip-addr", "0.0.0.0:4000", "--secret", "/app/keys/id.sec", "--loader", "/app/loader.pub", "--requester", "/app/requester.pub"]
```

**Note:** The `/app/id.sec` path is where Marlin Oyster injects the enclave's identity secret key.

### 5. Deploy via Marlin Oyster CVM CLI

```bash
# For AMD
oyster-cvm deploy --wallet-private-key <WALLET_PRIVATE_KEY> --duration-in-minutes 35 --docker-compose docker-compose.yml --arch amd64 
```

```bash
# For ARM
oyster-cvm deploy --wallet-private-key <WALLET_PRIVATE_KEY> --duration-in-minutes 35 --docker-compose docker-compose.yml
```

### 6. Verify Attestation

```bash
# Verify attestation using the image ID from deployment:
cargo run --release --target x86_64-unknown-linux-musl --bin verifier -- \
  --endpoint http://ENCLAVE_IP:1300/attestation/raw \
  --image-id "IMAGE_ID_FROM_DEPLOYMENT" \
  --app app.pub
```

The image ID is computed from PCR values (PCR0, PCR1, PCR2, PCR16) and can be found in the Marlin Oyster deployment logs.

### 7. Interact with Enclave

```bash
# Load data
cargo run --release --target x86_64-unknown-linux-musl --bin loader -- \
  --ip-addr ENCLAVE_IP:4000 --app app.pub --secret loader.sec

# Request computation result
cargo run --release --target x86_64-unknown-linux-musl --bin requester -- \
  --ip-addr ENCLAVE_IP:4000 --app app.pub --secret requester.sec
```

## Key Formats

This project uses **X25519** keys (32 bytes) for key exchange:

| File | Size | Description |
|------|------|-------------|
| `id.sec` | 32 bytes | Server's X25519 private key |
| `id.pub` | 32 bytes | Server's X25519 public key |
| `loader.sec` | 32 bytes | Loader client's private key |
| `loader.pub` | 32 bytes | Loader client's public key |
| `requester.sec` | 32 bytes | Requester client's private key |
| `requester.pub` | 32 bytes | Requester client's public key |
| `app.pub` | 32 bytes | Server's public key (extracted from attestation) |

## Cryptography

- **Key Exchange**: X25519 ECDH (Elliptic Curve Diffie-Hellman)
- **Encryption**: ChaCha20-Poly1305 AEAD
- **Attestation**: AWS Nitro NSM with certificate chain validation

## Project Structure

```
.
├── src/
│   ├── app.rs            # Main server (runs inside enclave)
│   ├── loader.rs         # Data loader client
│   ├── requester.rs      # Result requester client
│   ├── verifier.rs       # Attestation verifier
│   └── keygen.rs         # X25519 key generator
├── Dockerfile # Docker image for Marlin Oyster deployment
├── docker-compose.yml    # Marlin Oyster deployment config
├── aws.cert              # AWS root certificate for attestation verification
├── loader.pub            # Loader client's public key (embedded in Docker image)
├── requester.pub         # Requester client's public key (embedded in Docker image)
├── Cargo.toml            # Rust dependencies
└── Cargo.lock            # Locked dependency versions
```
## License

MIT
