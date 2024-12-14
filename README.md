
![cdlogo](https://carefuldata.com/images/cdlogo.png)

# wormsign

This is a CLI tool used to create [Dilithium](https://pq-crystals.org/dilithium/index.shtml) keys, signatures, and to verify signatures.

This tool includes a modified version of [dilithium library](https://github.com/Argyle-Software/dilithium). The modification is only to enable writing and reading keys from files, something that library doesn't yet have support for. The dilithium cryptography itself comes entirely from that library. Once support for the same functionality is included in that library (see https://github.com/Argyle-Software/dilithium/issues/11), I'll likely switch wormsign to pulling the library from crates.io normally.

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

## Wormsign Features

The most secure available defaults are set: Dilithium5, AES, and random signatures.

Those features can be adjusted at compile time in the `Cargo.toml`.

Defaults:

- "randomized signatures" enabled
- Dilithium-AES for AES-256 sampling and expanding instead of SHAKE
- Dilithium5 protected (AES-256 encrypted) signing key generation (-g)
- Dilithium5 file signing with ephemeral one-time-use signing (-ats)
- Dilithium5 file signing with encrypted key file (-s, -as)
- Dilithium5 signature verification (-v, -av)
