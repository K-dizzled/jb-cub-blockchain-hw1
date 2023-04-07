# RSA based signing of the data

## How to use
```bash
A simple CLI for generating and signing messages using RSA algorithm

Usage: rsa_signature <COMMAND>

Commands:
  gen-keys          Generates a new keypair to be used for signing and verifying
  sign              Signs a message with the given private key
  verify_signature  Verifies a message with the given public key
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## How to run
```bash
cargo build
echo "Hello world" > message.txt 
./target/debug/rsa_signature gen-keys my_key
./target/debug/rsa_signature sign message.txt my_key_private.pem signed_msg.txt
./target/debug/rsa_signature verify_signature message.txt my_key_public.pem signed_msg.txt
Signature is valid: true
```