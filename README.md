# wormsign

This is a CLI tool used to create [Dilithium](https://pq-crystals.org/dilithium/index.shtml) keys, signatures, and to verify signatures.

⚠️ Use at your own risk!

This tool includes a modified version of this [dilithium library](https://github.com/Argyle-Software/dilithium) to enable reading keys from files.

## Key encryption

The signing key is encrypted after generation and encrypted when not in use as of version 0.1.1. The encryption is AES-256 with a password.
The wormsign program prompts for a password on key generation and signing (but not verifying, since that is public key only).
The key is automatically encrypted again after signing is completed. A future version of wormsign might decrypt in memory instead of on disk.

<b>If an invalid password to decrypt the signing key is supplied while attempting to sign, wormsign will create a signature with the key ciphertext as the signing key, but that signature will not match the public key and verifications fail.</b>

## TOML config file

The tool uses a config file in the working directory named `wormsign.toml` to specify the keys, targets, and signature output locations. Edit that file to contain the values you want to use. There is an example `wormsign.toml` included that is as follows:

```
key_path = "./dilithium-private.key"
pub_path = "./dilithium-public.key"
sig_path = "./dilithium-signature.bin"
file_path = "./Cargo.toml"
```

So if I wanted to sign my new package `./workspace/things/thing1.rpm` I would set that as the `file_path`, and with that I might set the `sig_path` to something like `./workspace/things/thing1.rpm.dilithium-sig.bin`.

## Wormsign Features

As of version 0.1.1 the most secure defaults are set: Dilithium5, AES, and random signatures.

Those features can be adjusted at compile time in the `Cargo.toml`.

Defaults:

- Dilithium5 key generation (-g)
- Dilithium5 file signing (-s)
- Dilithium5 signature verification (-v)


