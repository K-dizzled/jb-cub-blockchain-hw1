use::clap::{arg, command, Command};
use rsa::signature::{Keypair,RandomizedSigner, SignatureEncoding, Verifier};
use rsa::sha2::{Sha256};
use rsa::{RsaPrivateKey};
use rsa::pkcs1::{LineEnding};
use std::fs::{File};
use std::io::Read;
use rsa::pkcs8::{DecodePublicKey, DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::pkcs1v15::{SigningKey, Signature, VerifyingKey};

fn main() {
    let matches = command!()
        .about("A simple CLI for generating and signing messages using RSA algorithm")
        .version("1.0")
        .author("Andrei Kozyrev")
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("gen-keys")
                .about("Generates a new keypair to be used for signing and verifying")
                .arg(arg!([OUTPUT] "The name of the output file").required(true)),
        )
        .subcommand(
            Command::new("sign")
                .about("Signs a message with the given private key")
                .arg(arg!([MESSAGE] "The message to sign, path to a .txt file").required(true))
                .arg(arg!([KEYFILE] "Path to the private key file").required(true))
                .arg(arg!([OUTPUT] "The output file to write the signed message to").required(true)),
        )
        .subcommand(
            Command::new("verify_signature")
                .about("Verifies a message with the given public key")
                .arg(arg!([MESSAGE] "Origin message, path to a .txt file").required(true))
                .arg(arg!([KEYFILE] "Path to the public key file").required(true))
                .arg(arg!([SIGNATURE] "Signed message to verify").required(true)),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("gen-keys", sub_matches)) => {
            let output = sub_matches.get_one::<String>("OUTPUT").unwrap();
            gen_keys(output);
        },
        Some(("sign", sub_matches)) => {
            let message = sub_matches.get_one::<String>("MESSAGE").unwrap();
            let keyfile = sub_matches.get_one::<String>("KEYFILE").unwrap();
            let output = sub_matches.get_one::<String>("OUTPUT").unwrap();
            sign(message, keyfile, output);
        },
        Some(("verify_signature", sub_matches)) => {
            let message = sub_matches.get_one::<String>("MESSAGE").unwrap();
            let keyfile = sub_matches.get_one::<String>("KEYFILE").unwrap();
            let signature = sub_matches.get_one::<String>("SIGNATURE").unwrap();
            verify_signature(message, keyfile, signature);
        },
        _ => unreachable!("Exhausted list of subcommands and subcommand_required prevents `None`"),
    }
}

fn gen_keys(output: &str) {
    let mut rng = rand::thread_rng();
    let public_key_file_name = format!("{}_public.pem", output);
    let private_key_file_name = format!("{}_private.pem", output);

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);
    let verifying_key = signing_key.verifying_key();

    let private_key_pem = signing_key.to_pkcs8_pem(LineEnding::LF).expect("Unable to write private key");
    std::fs::write(private_key_file_name, private_key_pem.as_bytes()).expect("Unable to write public key");

    verifying_key.write_public_key_pem_file(public_key_file_name.as_str(), LineEnding::LF).expect("Unable to write public key");
}

fn sign(message: &str, keyfile: &str, output: &str) {
    let mut rng = rand::thread_rng();
    let message = std::fs::read_to_string(message).expect("Unable to read message");
    let private_key_pem = std::fs::read_to_string(keyfile).expect("Unable to read private key");
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem.as_str()).expect("Unable to parse private key");
    let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);
    let signature = signing_key.sign_with_rng(&mut rng, message.as_bytes());
    let signed_msg = signature.to_bytes();
    std::fs::write(output, signed_msg.as_ref()).expect("Unable to write signed message");
}

fn verify_signature(message: &str, keyfile: &str, signature: &str) {
    let public_key = DecodePublicKey::read_public_key_pem_file(keyfile).expect("Unable to parse public key");
    let verifying_key = VerifyingKey::<Sha256>::new_with_prefix(public_key);
    let orig_msg = std::fs::read_to_string(message).expect("Unable to read message");

    let mut signed_msg = Vec::new();
    File::open(signature).expect("Unable to open input file")
        .read_to_end(&mut signed_msg)
        .expect("Unable to read input file");

    let sign = signed_msg.into_boxed_slice();

    let signature = Signature::from(sign);
    let verified = verifying_key.verify(orig_msg.as_bytes(), &signature);
    println!("Signature is valid: {}", verified.is_ok());
}