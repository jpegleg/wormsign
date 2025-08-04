![cdlogo](https://carefuldata.com/images/cdlogo.png)

# wormsign

This is a CLI tool used to create [Dilithium](https://pq-crystals.org/dilithium/index.shtml) keys, signatures, and to verify signatures.

This tool includes a modified version of this [dilithium library](https://github.com/Argyle-Software/dilithium). The modification is to enable writing and reading keys from files, something that library doesn't yet have support for. Additionally wormsign has modified that dilithium library to upgrade the `rand` crate and will maintain the library within itself as long as needed. The dilithium cryptography itself comes entirely from that library.

Wormsign is available on crates.io and can be installed using `cargo`:

```
cargo install wormsign
```

It can of course be compiled from source and installed:

```
cargo build --release
sudo cp target/release/wormsign /usr/local/bin/wormsign

```

Also see the releases section on github for binary downloads: https://github.com/jpegleg/wormsign/releases/

## Usage

The `wormsign` options `-g`, `-s`, and `-v` can be used on their own, or in any combination.

Creating a new keypair, signing, and verifying all at once:

```
$ vim wormsign.toml # populate the values as desired
$ wormsign -g -s -v # generate a new key, sign, and verify all at once
```

Signing a file:

```
$ vim wormsign.toml # populate the values as desired using an existing wormsign key
$ wormsign -s # sign with the existing key
```

Verifying a file and signature with a public key:

```
$ vim wormsign.toml # populate the values to verify, note that key_path isn't used during verification so key_path = "" is valid but key_path must be in the wormsign.toml
$ wormsign -v # verify only
```

Generating a new signing key:

```
$ vim wormsign.toml # populate as desired
$ wormsign -g # generate a keypair only
```

## Key encryption

The signing key is encrypted after generation before writing to disk, and left as ciphertext on the disk. When signing, wormsign reads the ciphertext and decrypts the signing key in (RAM) only.

<b>If an invalid password to decrypt the signing key is supplied while attempting to sign, wormsign will create a signature with the key ciphertext as the signing key, but that signature will not match the public key and verifications then fail.</b>

## One-time-use signing

When the `-ats` option is passed to `wormsign`, instead of reading the key files, a new key is generated for the signing and only the public key is saved.

## Skipping metadata output

The `-as` and `-av` options are the same as `-s` and `-v` but without the file metadata collection. This is useful when that information is not desired or not supported.

## TOML config file

The tool uses a config file in the working directory named `wormsign.toml` to specify the keys, targets, and signature output locations. Edit that file to contain the values you want to use. There is an example `wormsign.toml` included that is as follows:

```
key_path = "./dilithium-private.key"
pub_path = "./dilithium-public.key"
sig_path = "./dilithium-signature.bin"
file_path = "./Cargo.toml"
```

So if I wanted to sign my new package `./workspace/things/thing1.rpm` I would set that as the `file_path`, and with that I might set the `sig_path` to something like `./workspace/things/thing1.rpm.dilithium-sig.bin`.

Each value is required, even if not used. For example, even when doing a verification with no key, a key_path must be set. For cases like this, we can set the key_path to anything, such as `NA`.

A wormsign.toml is required to use any features of wormsign.

The `wormsign-confgen` tool can be used to generate a `wormsign.toml` based on arguments passed to `wormsign-confgen`. See more about the wormsign-confgen tool in the section below.

## Wormsign Features

The most secure available defaults are set: Dilithium5 and random signatures.

The AES mode instead of SHAKE is helpful for increasing speed on some hardware.

Those features can be adjusted at compile time in the `Cargo.toml`.

Defaults:

- "randomized signatures" enabled
- Dilithium-AES for AES-256 sampling and expanding instead of SHAKE
- Dilithium5 protected (AES-256 encrypted) signing key generation (-g)
- Dilithium5 file signing with ephemeral one-time-use signing (-ats)
- Dilithium5 file signing with encrypted key file (-s, -as)
- Dilithium5 signature verification (-v, -av)

## Project promises

This project will never use AI-slop. All code is reviewed, tested, implemented by a human that is academically trained in cryptography and information security.
This repository and the crates.io repository is carefully managed and protected.

This project will never break backwards compatibility in releases regarding the signature validation.

This project will be maintained as best as is reasonable.

## wormsign-confgen, the config generation tool

There is a tool included that can generate `wormsign.toml` files from CLI arguments named `wormsign-confgen`.

Pass in the arguments to `wormsign-confgen` like so:

`wormsign-confgen <file_path> <pub_key_path> <sig_path> <private_key_path>`

Wormsign-confgen is especially useful for fully automated/scripted uses.

## Additional scripting with Elvish

If you use the [elvish](https://elv.sh/r) shell, I have included some examples in [elvish-pathway](https://github.com/jpegleg/elvish-pathway/tree/main), including this script to bulk sign https://github.com/jpegleg/elvish-pathway/blob/main/scripts/usul.elv.
