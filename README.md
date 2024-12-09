# wormsign

This is a tool design for Linux CLI use to create [Dilithium](https://pq-crystals.org/dilithium/index.shtml) keys, signatures, and to verify signatures.

⚠️ Use at your own risk!

This tool includes a modified version of this [dilithium library](https://github.com/Argyle-Software/dilithium) to enable reading keys from files.

## Version 1.0 is rough

There are a number of improvements to make to this tool. More error handling and security features are in progress.

## TOML config file

The tool uses a config file in the working directory named `wormsign.toml` to specify the keys, targets, and signature output locations. Edit that file to contain the values you want to use. There is an example `wormsign.toml` included that is as follows:

```
key_path = "./dilithium-private.key"
pub_path = "./dilithium-public.key"
sig_path = "./dilithium-signature.bin"
file_path = "./Cargo.toml"
```

So if I wanted to sign my new package `./workspace/things/thing1.rpm` I would set that as the `file_path`.

Similarly, I met set the `sig_path` to something like `./workspace/things/thing1.rpm.dilithium-sig.bin`.

## Wormsign Features

- Dilithium3 key generation (-g)
- Dilithium3 file signing (-s)
- Dilithium3 signature verification (-v)
