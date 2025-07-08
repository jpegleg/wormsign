use std::fs::File;
use std::env;
use std::io::{self, Write};

/// Supply the path to the file to sign, the private key path, the public key path, and the signature path.
/// When used for verification, the private key value still must be set to something, even if no private key is used.
/// Suggest using a something like "./NA" or "./verify_only" etc etc, so it is clear that no real private key is used,
/// especially when the system is made for verification only.
fn write_config(file_path: &str, key: &str, pub_key: &str, sig_path: &str) -> io::Result<()> {
    let config_content = format!(
        r#"key_path = "{}"
pub_path = "{}"
sig_path = "{}"
file_path = "{}"
"#,
        key, pub_key, sig_path, file_path
        );
    let mut file = File::create("./wormsign.toml")?;
    file.write_all(config_content.as_bytes())?;
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        eprintln!("Usage: wormsign-confgen <file_path> <pub_path> <sig_path> <key_path>");
        std::process::exit(1);
    }

    let file_path = &args[1];
    let pub_path = &args[2];
    let sig_path = &args[3];
    let key_path = &args[4];
    write_config(file_path, key_path, pub_path, sig_path)?;
    Ok(())
}
