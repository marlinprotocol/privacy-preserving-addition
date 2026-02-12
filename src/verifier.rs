use aws_nitro_enclaves_cose::{crypto::Openssl, crypto::SigningPublicKey, CoseSign1};
use clap::Parser;
use hex;
use hyper::{client::Client, Uri};
use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::x509::{X509VerifyResult, X509};
use serde_cbor::{self, value, value::Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use tokio;

fn get_all_certs(cert: X509, cabundle: Vec<Value>) -> Result<Vec<X509>, ErrorStack> {
    let mut all_certs = Vec::new();
    all_certs.push(cert);
    for cert in cabundle {
        let intermediate_certificate = match cert {
            Value::Bytes(b) => b,
            _ => unreachable!(),
        };
        let intermediate_certificate = X509::from_der(&intermediate_certificate)?;
        all_certs.push(intermediate_certificate);
    }
    Ok(all_certs)
}

fn verify_cert_chain(
    cert: X509,
    cabundle: Vec<Value>,
    root_cert_pem: Vec<u8>,
    attestation_time: i64,
) -> Result<(), Box<dyn Error>> {
    let certs = get_all_certs(cert, cabundle)?;
    // Use attestation timestamp for validation, not current system time
    let attestation_asn1_time = Asn1Time::from_unix(attestation_time)?;
    let mut i = 0;
    while i < certs.len() - 1 {
        let pubkey = certs[i + 1].public_key()?;
        let x = certs[i].verify(&pubkey)?;
        if !x {
            return Err("signature verification failed".into());
        }
        let x = certs[i + 1].issued(&certs[i]);
        if x != X509VerifyResult::OK {
            return Err("certificate issuer and subject verification failed".into());
        }
        if certs[i].not_after() < attestation_asn1_time || certs[i].not_before() > attestation_asn1_time {
            return Err("certificate timestamp expired/not valid".into());
        }
        i += 1;
    }
    let root_cert = X509::from_pem(&root_cert_pem)?;
    if &root_cert != certs.last().unwrap() {
        return Err("root certificate mismatch".into());
    }
    Ok(())
}

fn compute_image_id(pcr0: &[u8], pcr1: &[u8], pcr2: &[u8], pcr16: &[u8]) -> String {
    let mut hasher = Sha256::new();

    // Bitflags: PCR 0, 1, 2, 16
    let bitflags: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 16);
    hasher.update(&bitflags.to_be_bytes());

    // PCR values (48 bytes each)
    hasher.update(pcr0);
    hasher.update(pcr1);
    hasher.update(pcr2);
    hasher.update(pcr16);

    hex::encode(hasher.finalize())
}

fn extract_pcr(pcrs_map: &mut BTreeMap<Value, Value>, index: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let pcr = pcrs_map
        .remove(&value::to_value(index).unwrap())
        .ok_or(Box::<dyn Error>::from(format!("pcr{} not found", index)))?;
    match pcr {
        Value::Bytes(b) => Ok(b),
        _ => Err(format!("pcr{} is not bytes", index).into()),
    }
}

fn extract_pcr_optional(pcrs_map: &mut BTreeMap<Value, Value>, index: u64) -> Vec<u8> {
    match pcrs_map.remove(&value::to_value(index).unwrap()) {
        Some(Value::Bytes(b)) => b,
        _ => vec![0u8; 48], // Default to zeros if not present
    }
}

fn verify(
    attestation_doc_cbor: Vec<u8>,
    root_cert_pem: Vec<u8>,
    expected_image_id: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let cosesign1 = CoseSign1::from_bytes(&attestation_doc_cbor)?;
    let payload = cosesign1.get_payload::<Openssl>(None as Option<&dyn SigningPublicKey>)?;
    let mut attestation_doc: BTreeMap<Value, Value> =
        value::from_value(serde_cbor::from_slice::<Value>(&payload)?)?;

    // Extract PCRs
    let document_pcrs_arr = attestation_doc
        .remove(&value::to_value("pcrs").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "pcrs key not found in attestation doc",
        ))?;
    let mut document_pcrs_arr: BTreeMap<Value, Value> = value::from_value(document_pcrs_arr)?;

    let pcr0 = extract_pcr(&mut document_pcrs_arr, 0)?;
    let pcr1 = extract_pcr(&mut document_pcrs_arr, 1)?;
    let pcr2 = extract_pcr(&mut document_pcrs_arr, 2)?;
    let pcr16 = extract_pcr_optional(&mut document_pcrs_arr, 16);

    // Compute and verify image_id
    let computed_image_id = compute_image_id(&pcr0, &pcr1, &pcr2, &pcr16);
    if computed_image_id != expected_image_id {
        return Err(format!(
            "image_id mismatch: expected {}, got {}",
            expected_image_id, computed_image_id
        )
        .into());
    }

    // Verify COSE signature
    let enclave_certificate = attestation_doc
        .remove(&value::to_value("certificate").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "certificate key not found in attestation doc",
        ))?;
    let enclave_certificate = match enclave_certificate {
        Value::Bytes(b) => b,
        _ => unreachable!(),
    };
    let enclave_certificate = X509::from_der(&enclave_certificate)?;
    let pub_key = enclave_certificate.public_key()?;
    let verify_result = cosesign1.verify_signature::<Openssl>(&pub_key)?;

    if !verify_result {
        return Err("cose signature verification failed".into());
    }

    // Extract timestamp from attestation doc (in milliseconds)
    let timestamp = attestation_doc
        .remove(&value::to_value("timestamp").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "timestamp not found in attestation doc",
        ))?;
    let timestamp: i64 = match timestamp {
        Value::Integer(i) => i.try_into()?,
        _ => return Err("timestamp is not an integer".into()),
    };

    // Verify certificate chain
    let cabundle = attestation_doc
        .remove(&value::to_value("cabundle").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "cabundle key not found in attestation doc",
        ))?;

    let mut cabundle: Vec<Value> = value::from_value(cabundle)?;
    cabundle.reverse();

    // Pass timestamp in seconds (AWS Nitro uses milliseconds)
    verify_cert_chain(enclave_certificate, cabundle, root_cert_pem, timestamp / 1000)?;

    // Extract public key
    let public_key = attestation_doc
        .remove(&value::to_value("public_key").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "public key not found in attestation doc",
        ))?;
    let public_key = match public_key {
        Value::Bytes(b) => b,
        _ => unreachable!(),
    };

    Ok(public_key)
}

#[tokio::main]
async fn get_attestation_doc(endpoint: String) -> Result<Vec<u8>, Box<dyn Error>> {
    let client = Client::new();
    let res = client.get(endpoint.parse::<Uri>()?).await?;
    let buf = hyper::body::to_bytes(res).await?;
    Ok(buf.to_vec())
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Attestation endpoint http://<ip:port>/attestation/raw
    #[clap(short, long, value_parser)]
    endpoint: String,

    /// Path to output app public key file
    #[arg(short, long)]
    app: String,

    /// Expected image ID (hex-encoded)
    #[arg(short, long)]
    image_id: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let attestation_doc = get_attestation_doc(cli.endpoint)?;
    let cert = include_bytes!("../aws.cert").to_vec();

    let pub_key = verify(attestation_doc, cert, &cli.image_id)?;
    println!("verification successful with pubkey: {:?}", pub_key);

    let mut file = File::create(cli.app)?;
    file.write_all(pub_key.as_slice())?;

    Ok(())
}
