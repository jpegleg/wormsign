use std::env;
use std::error::Error as StdError;
use std::os::unix::fs::{PermissionsExt, MetadataExt};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::io::{self, Read, Write};
use serde::Deserialize;
use sha3::{Shake256, digest::{Update, ExtendableOutput}};
use chrono::{TimeZone, NaiveDateTime, DateTime, Utc};
use uzers::{get_user_by_uid, get_group_by_gid};
use rpassword::read_password;

use wormsign::Keypair;
use wormsign::verify;
use wormsign::keygen;

mod aesrest;

/// The Config struct is required, parsed from wormsign.toml.
#[derive(Deserialize)]
struct Config {
    key_path: String,
    pub_path: String,
    sig_path: String,
    file_path: String,
}

/// Wormsign forces errors to JSON. This function is a wrapper for STDERR to JSON.
fn print_error_json(msg: &str) {
    // This is a simple wrapper for STDERR JSON error printing.
    eprintln!(r#"{{"Error":"{}"}}"#, msg);
}

/// This macro rule is used to catch errors and force them to JSON.
/// The json_started variable is manually set when the printing of
/// a JSON body has already begun, so we can complete the printing
/// of a valid JSON body, catching mid-processing issues and ensuring
/// the output is always valid JSON.
macro_rules! try_print_json {
    ($expr:expr, $json_started:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                if $json_started {
                    println!("  \"Error\": \"{}\"", e);
                    println!(" }}");
                    println!("}}");
                    return Ok(());
                } else {
                    return Err(Box::new(e) as Box<dyn StdError>);
                }
            }
        }
    };
}


/// This is the verification function used to verify a Dilithium signature.
#[allow(deprecated)]
fn verf(file_path: &str, pub_path: &str, sig_path: &str) -> Result<(), Box<dyn StdError>> {
    let mut json_started = false;
    let file_path = Path::new(file_path);
    let metadata = try_print_json!(
        file_path.metadata().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file metadata: {}", e))),
        json_started
    );
    let mut file = try_print_json!(
        File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path.display(), e))),
        json_started
    );
    let mut bytes = Vec::new();
    try_print_json!(
        file.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file {}: {}", file_path.display(), e))),
        json_started
    );
    let num_bytes = bytes.len();
    let num_bits = num_bytes * 8;
    let byte_distribution = bytes.iter().collect::<std::collections::HashSet<_>>().len() as f64 / num_bytes as f64;
    let file_is_open = match OpenOptions::new().read(true).write(true).open(file_path) {
        Ok(_) => false,
        Err(_) => true,
    };
    let chronox: String = Utc::now().to_string();
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    let mut resulto = hasher.finalize_xof();
    let mut shake256 = [0u8; 10];
    let _ = resulto.read(&mut shake256);
    json_started = true;
    println!("{{");
    println!("{:?}: {{", file_path);
    println!("  \"Checksum SHA3 SHAKE256 10\": \"{:?}\",", shake256);
    println!("  \"Report time\": \"{}\",", chronox);
    let num_io_blocks = metadata.blocks();
    println!("  \"Number of IO blocks\": \"{}\",", num_io_blocks);
    let blocksize = metadata.blksize();
    println!("  \"Block size\": \"{}\",", blocksize);
    let inode = metadata.ino();
    println!("  \"Inode\": \"{}\",", &inode);
    println!("  \"Total as bytes\": \"{}\",", &num_bytes);
    println!("  \"Total as kilobytes\": \"{}\",", &num_bytes / 1024);
    println!("  \"Total as megabytes\": \"{}\",", &num_bytes / (1024 * 1024));
    println!("  \"Total as bits\": \"{}\",", num_bits);
    println!("  \"Byte distribution\": \"{}\",", byte_distribution);
    let created: DateTime<Utc> = try_print_json!(
        metadata.created().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get created timestamp.")).map(DateTime::from),
        json_started
    );
    let modified: DateTime<Utc> = try_print_json!(
        metadata.modified().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get modified timestamp.")).map(DateTime::from),
        json_started
    );
    let access: DateTime<Utc> = try_print_json!(
        metadata.accessed().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get accessed timestamp.")).map(DateTime::from),
        json_started
    );
    let changed: DateTime<Utc> = {
        let ctime = metadata.ctime();
        let ctimesec = metadata.ctime_nsec() as u32;
        let naive_datetime = try_print_json!(
            NaiveDateTime::from_timestamp_opt(ctime, ctimesec).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid changed timestamp")),
            json_started
        );
        TimeZone::from_utc_datetime(&Utc, &naive_datetime)
    };
    println!("  \"Created timestamp (UTC)\": \"{}\",", created);
    println!("  \"Modified timestamp (UTC)\": \"{}\",", modified);
    println!("  \"Accessed timestamp (UTC)\": \"{}\",", access);
    println!("  \"Changed timestamp (UTC)\": \"{}\",", changed);
    let permission = metadata.permissions();
    let mode = permission.mode();
    println!("  \"Permissions\": \"{:o}\",", mode);
    let uid = metadata.uid();
    let gid = metadata.gid();
    let owner = match get_user_by_uid(uid) {
        Some(user) => user.name().to_string_lossy().into_owned(),
        None => "-".to_string(),
    };
    let group = match get_group_by_gid(gid) {
        Some(group) => group.name().to_string_lossy().into_owned(),
        None => "-".to_string(),
    };
    println!("  \"Owner\": \"{} (uid: {})\",", owner, uid);
    println!("  \"Group\": \"{} (gid: {})\",", group, gid);
    if file_is_open {
        println!("  \"Open\": \"File is currently open by another program... verifying anyway!\",");
    } else {
        println!("  \"Open\": \"File is not open by another program. Verifying...\",");
    }
    let mut kfile = try_print_json!(
        File::open(&pub_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the key: {}", e))),
        json_started
    );
    let mut kbytes = Vec::new();
    try_print_json!(
        kfile.read_to_end(&mut kbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the key: {}", e))),
        json_started
    );
    let mut sfile = try_print_json!(
        File::open(&sig_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the signature file: {}", e))),
        json_started
    );
    let mut sbytes = Vec::new();
    try_print_json!(
        sfile.read_to_end(&mut sbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the signature file: {}", e))),
        json_started
    );
    let msg = &bytes;
    let sig_verify = verify(&sbytes, &msg, &kbytes);
    let statusig = sig_verify.is_ok();
    println!("  \"Verification Result\": \"{}\"", statusig);
    println!(" }}");
    println!("}}");
    Ok(())
}

/// This is an alternative verification function that skips collecting UNIX metdata.
/// This is the version to use when UNIX metadata isn't supported, such as on Window or UNIX-like
/// distributions that don't support the file metadata collection, such as Alpine Linux.
#[allow(deprecated)]
fn averf(file_path: &str, pub_path: &str, sig_path: &str) -> Result<(), Box<dyn StdError>> {
    let json_started = true;
    let file_path = Path::new(file_path);
    println!("{{");
    println!("{:?}: {{", file_path);
    let mut bytes = Vec::new();
    let mut file = try_print_json!(
        File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path.display(), e))),
        json_started
    );
    try_print_json!(
        file.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file {}: {}", file_path.display(), e))),
        json_started
    );
    let mut kfile = try_print_json!(
        File::open(&pub_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the key: {}", e))),
        json_started
    );
    let mut kbytes = Vec::new();
    try_print_json!(
        kfile.read_to_end(&mut kbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the key: {}", e))),
        json_started
    );
    let mut sfile = try_print_json!(
        File::open(&sig_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the signature file: {}", e))),
        json_started
    );
    let mut sbytes = Vec::new();
    try_print_json!(
        sfile.read_to_end(&mut sbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the signature file: {}", e))),
        json_started
    );
    let msg = &bytes;
    let sig_verify = verify(&sbytes, &msg, &kbytes);
    let statusig = sig_verify.is_ok();
    println!("  \"Verification Result\": \"{}\"", statusig);
    println!(" }}");
    println!("}}");
    Ok(())
}


/// This function creates a Dilithium signature.
#[allow(deprecated)]
fn sig(file_path: &str, key_path: &str, pub_path: &str, sig_path: &str) -> Result<(), Box<dyn StdError>> {
    let mut json_started = false;
    // STDERR on prompt so that output stays valid JSON, useful for redirects etc
    eprintln!("Enter key password then press enter (will not be displayed):");
    std::io::stdout().flush().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to flush stdout: {}", e)))?;
    let password = read_password().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read password: {}", e)))?;
    let keymaterial = aesrest::derive_key(password.as_bytes(), 32);
    let kbytes = aesrest::decrypt_key(key_path, &keymaterial)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to decrypt key: {}", e)))?;
    let file_path = Path::new(file_path);
    let metadata = try_print_json!(
        file_path.metadata().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file metadata: {}", e))),
        json_started
    );
    let mut file = try_print_json!(
        File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path.display(), e))),
        json_started
    );
    let mut bytes = Vec::new();
    try_print_json!(
        file.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file {}: {}", file_path.display(), e))),
        json_started
    );
    let num_bytes = bytes.len();
    let num_bits = num_bytes * 8;
    let byte_distribution = bytes.iter().collect::<std::collections::HashSet<_>>().len() as f64 / num_bytes as f64;
    let file_is_open = match OpenOptions::new().read(true).write(true).open(file_path) {
        Ok(_) => false,
        Err(_) => true,
    };
    let chronox: String = Utc::now().to_string();
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    let mut resulto = hasher.finalize_xof();
    let mut shake256 = [0u8; 10];
    let _ = resulto.read(&mut shake256);
    json_started = true;
    println!("{{");
    println!("{:?}: {{", file_path);
    println!("  \"Checksum SHA3 SHAKE256 10\": \"{:?}\",", shake256);
    println!("  \"Report time\": \"{}\",", chronox);
    let num_io_blocks = metadata.blocks();
    println!("  \"Number of IO blocks\": \"{}\",", num_io_blocks);
    let blocksize = metadata.blksize();
    println!("  \"Block size\": \"{}\",", blocksize);
    let inode = metadata.ino();
    println!("  \"Inode\": \"{}\",", &inode);
    println!("  \"Total as bytes\": \"{}\",", &num_bytes);
    println!("  \"Total as kilobytes\": \"{}\",", &num_bytes / 1024);
    println!("  \"Total as megabytes\": \"{}\",", &num_bytes / (1024 * 1024));
    println!("  \"Total as bits\": \"{}\",", num_bits);
    println!("  \"Byte distribution\": \"{}\",", byte_distribution);
    let created: DateTime<Utc> = try_print_json!(
        metadata.created().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get created timestamp.")).map(DateTime::from),
        json_started
    );
    let modified: DateTime<Utc> = try_print_json!(
        metadata.modified().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get modified timestamp.")).map(DateTime::from),
        json_started
    );
    let access: DateTime<Utc> = try_print_json!(
        metadata.accessed().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get accessed timestamp.")).map(DateTime::from),
        json_started
    );
    let changed: DateTime<Utc> = {
        let ctime = metadata.ctime();
        let ctimesec = metadata.ctime_nsec() as u32;
        let naive_datetime = try_print_json!(
            NaiveDateTime::from_timestamp_opt(ctime, ctimesec).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid changed timestamp")),
            json_started
        );
        TimeZone::from_utc_datetime(&Utc, &naive_datetime)
    };
    println!("  \"Created timestamp (UTC)\": \"{}\",", created);
    println!("  \"Modified timestamp (UTC)\": \"{}\",", modified);
    println!("  \"Accessed timestamp (UTC)\": \"{}\",", access);
    println!("  \"Changed timestamp (UTC)\": \"{}\",", changed);
    let permission = metadata.permissions();
    let mode = permission.mode();
    println!("  \"Permissions\": \"{:o}\",", mode);
    let uid = metadata.uid();
    let gid = metadata.gid();
    let owner = match get_user_by_uid(uid) {
        Some(user) => user.name().to_string_lossy().into_owned(),
        None => "-".to_string(),
    };
    let group = match get_group_by_gid(gid) {
        Some(group) => group.name().to_string_lossy().into_owned(),
        None => "-".to_string(),
    };
    println!("  \"Owner\": \"{} (uid: {})\",", owner, uid);
    println!("  \"Group\": \"{} (gid: {})\",", group, gid);
    if file_is_open {
        println!("  \"Open\": \"File is currently open by another program... signing anyway!\",");
    } else {
        println!("  \"Open\": \"File is not open by another program. Signing...\",");
    }
    let keypath = Path::new(&key_path);
    let pubpath = Path::new(&pub_path);
    let kmetadata = try_print_json!(
        keypath.metadata().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file metadata for key: {}", e))),
        json_started
    );
    let mut kpubf = try_print_json!(
        File::open(&pubpath).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the public key: {}", e))),
        json_started
    );
    let mut pubbytes = Vec::new();
    try_print_json!(
        kpubf.read_to_end(&mut pubbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the public key: {}", e))),
        json_started
    );
    let keys: Keypair = Keypair::loadit(pubbytes, kbytes);
    let msg = &bytes;
    let sig = keys.sign(&msg);
    let spath = Path::new(sig_path);
    let mut sigoutput = try_print_json!(
        File::create(spath).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create signature file {}: {}", sig_path, e))),
        json_started
    );
    try_print_json!(
        sigoutput.write_all(&sig).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to write signature: {}", e))),
        json_started
    );
    println!("  \"Dilithium signature file\": \"{}\",", sig_path);
    println!("  \"Dilithium signing key\": \"{}\",", key_path);
    let kinode = kmetadata.ino();
    println!("  \"Key Inode\": \"{}\",", &kinode);
    let kcreated: DateTime<Utc> = try_print_json!(
        kmetadata.created().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get key created timestamp.")).map(DateTime::from),
        json_started
    );
    let kmodified: DateTime<Utc> = try_print_json!(
        kmetadata.modified().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get key modified timestamp.")).map(DateTime::from),
        json_started
    );
    let kaccess: DateTime<Utc> = try_print_json!(
        kmetadata.accessed().map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to get key accessed timestamp.")).map(DateTime::from),
        json_started
    );
    let kchanged: DateTime<Utc> = {
        let ctime = kmetadata.ctime();
        let ctimesec = kmetadata.ctime_nsec() as u32;
        let naive_datetime = try_print_json!(
            chrono::NaiveDateTime::from_timestamp_opt(ctime, ctimesec).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid key changed timestamp")),
            json_started
        );
        TimeZone::from_utc_datetime(&Utc, &naive_datetime)
    };
    println!("  \"Key Created timestamp (UTC)\": \"{}\",", kcreated);
    println!("  \"Key Modified timestamp (UTC)\": \"{}\",", kmodified);
    println!("  \"Key Accessed timestamp (UTC)\": \"{}\",", kaccess);
    println!("  \"Key Changed timestamp (UTC)\": \"{}\",", kchanged);
    let kpermission = kmetadata.permissions();
    let kmode = kpermission.mode();
    println!("  \"Key Permissions\": \"{:o}\",", kmode);
    let kuid = kmetadata.uid();
    let kgid = kmetadata.gid();
    let kowner = match get_user_by_uid(kuid) {
        Some(user) => user.name().to_string_lossy().into_owned(),
        None => "-".to_string(),
    };
    let kgroup = match get_group_by_gid(kgid) {
        Some(group) => group.name().to_string_lossy().into_owned(),
        None => "-".to_string(),
    };
    println!("  \"Key Owner\": \"{} (uid: {})\",", kowner, uid);
    println!("  \"Key Group\": \"{} (gid: {})\"", kgroup, gid);
    println!(" }}");
    println!("}}");
    Ok(())
}

/// The alternative signature function skips metadata collection. This is useful for platforms that don't support
/// the UNIX-based file metadata, such as Windows and UNIX-like distributions that don't suppor the file metadata
/// such as Alpine Linux.
#[allow(deprecated)]
fn asig(file_path: &str, key_path: &str, pub_path: &str, sig_path: &str) -> Result<(), Box<dyn StdError>> {
    let json_started = true;
    // STDERR on prompt so that output stays valid JSON, useful for redirects etc
    eprintln!("Enter key password then press enter (will not be displayed):");
    std::io::stdout().flush().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to flush stdout: {}", e)))?;
    let password = read_password().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read password: {}", e)))?;
    let keymaterial = aesrest::derive_key(password.as_bytes(), 32);
    let kbytes = aesrest::decrypt_key(key_path, &keymaterial)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to decrypt key: {}", e)))?;
    let file_path = Path::new(file_path);
    println!("{{");
    println!("{:?}: {{", file_path);
    let pubpath = Path::new(&pub_path);
    let mut kpubf = try_print_json!(
        File::open(&pubpath).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the public key: {}", e))),
        json_started
    );
    let mut bytes = Vec::new();
    let mut file = try_print_json!(
        File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path.display(), e))),
        json_started
    );
    try_print_json!(
        file.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file {}: {}", file_path.display(), e))),
        json_started
    );
    let mut pubbytes = Vec::new();
    try_print_json!(
        kpubf.read_to_end(&mut pubbytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read the public key: {}", e))),
        json_started
    );
    let keys: Keypair = Keypair::loadit(pubbytes, kbytes);
    let msg = &bytes;
    let sig = keys.sign(&msg);
    let spath = Path::new(sig_path);
    let mut sigoutput = try_print_json!(
        File::create(spath).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create signature file {}: {}", sig_path, e))),
        json_started
    );
    try_print_json!(
        sigoutput.write_all(&sig).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to write signature: {}", e))),
        json_started
    );
    println!("  \"Dilithium signature file\": \"{}\",", sig_path);
    println!("  \"Dilithium signing key\": \"{}\"", key_path);
    println!(" }}");
    println!("}}");
    Ok(())
}

/// This function creates a Dilithium signature and throws away the key, a one-time-use signature.
/// The public key can then be used to verify the signature later, but no further sigantures can
/// be made from the private key used.
#[allow(deprecated)]
fn autosig(file_path: &str, pub_path: &str, sig_path: &str) -> Result<(), Box<dyn StdError>> {
    let json_started = true;
    let file_path = Path::new(file_path);
    println!("{{");
    println!("{:?}: {{", file_path);
    let mut bytes = Vec::new();
    let mut file = try_print_json!(
        File::open(&file_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open file {}: {}", file_path.display(), e))),
        json_started
    );
    try_print_json!(
        file.read_to_end(&mut bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file {}: {}", file_path.display(), e))),
        json_started
    );
    let keys: Keypair = Keypair::generate();
    let mut pubout = try_print_json!(
        File::create(pub_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create public key file {}: {}", pub_path, e))),
        json_started
    );
    try_print_json!(
        pubout.write_all(&keys.public).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to write public key to file: {}", e))),
        json_started
    );

    let msg = &bytes;
    let sig = keys.sign(&msg);
    let spath = Path::new(sig_path);
    let mut sigoutput = try_print_json!(
        File::create(spath).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create signature file {}: {}", sig_path, e))),
        json_started
    );
    try_print_json!(
        sigoutput.write_all(&sig).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to write signature: {}", e))),
        json_started
    );
    println!("  \"Dilithium signature file\": \"{}\",", sig_path);
    println!("  \"Dilithium public key\": \"{}\"", pub_path);
    println!(" }}");
    println!("}}");
    Ok(())
}

/// A function that does "nothing successfully".
/// This is a "null" and "invalid" case handler.
fn donkout() -> Result<(), Box<dyn StdError>> {
    Ok(())
}

/// Print CLI help information.
fn help() -> Result<(), Box<dyn StdError>> {
    println!("wormsign - a program for creating Dilithium5-AES keypairs, \
        signatures, and verifying Dilithium5 signatures\n\n  -v verify \n  -s sign\n  -g generate keypair\n  -av verify without metadata collection\n  -as sign without metadata collection\n  -ats autonomous sign with one-time-use key (private key not saved)\n  -h print this menu\n  --version print the wormsign version\n");
    Ok(())
}

/// Print the version.
fn version() -> Result<(), Box<dyn StdError>> {
    println!("{{\"Version\": \"0.1.13\"}}");
    Ok(())
}

/// The main function is a wrapper for the run function, for error catching.
fn main() {
    if let Err(e) = run() {
        print_error_json(&e.to_string());
        std::process::exit(1);
    }
}

/// This function runs wormsign, a wrapper for the other functions and CLI options.
fn run() -> Result<(), Box<dyn StdError>> {
    let mut file = File::open("./wormsign.toml")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open wormsign.toml: {}", e)))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read wormsign.toml: {}", e)))?;
    let config: Config = toml::from_str(&contents)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse wormsign.toml")))?;
    let args: Vec<String> = env::args().collect();
    let file_path = &config.file_path;
    let pub_path = &config.pub_path;
    let sig_path = &config.sig_path;
    let key_path = &config.key_path;
    for arg in args.iter() {
        match arg.as_str() {
            "-v" => verf(file_path, pub_path, sig_path)?,
            "-av" => averf(file_path, pub_path, sig_path)?,
            "-g" => keygen(key_path, pub_path)?,
            "-s" => sig(file_path, key_path, pub_path, sig_path)?,
            "-as" => asig(file_path, key_path, pub_path, sig_path)?,
            "-ats" => autosig(file_path, pub_path, sig_path)?,
            "-h" => help()?,
            "--version" => version()?,
            _ => donkout()?
        }
    }
    Ok(())
}
