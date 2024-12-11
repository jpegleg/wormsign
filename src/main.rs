use std::env;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::fs::OpenOptions;
use std::io::{Read, Write};

use serde::Deserialize;
use sha3::{Shake256, digest::{Update, ExtendableOutput}};
use chrono::{NaiveDateTime, DateTime, Utc};
use users::{get_user_by_uid, get_group_by_gid};
use rpassword::read_password;

use wormsign::Keypair;
use wormsign::verify;

mod aesrest;

#[derive(Deserialize)]
struct Config {
    key_path: String,
    pub_path: String,
    sig_path: String,
    file_path: String,
}

fn keygen(key_path: &str, pub_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let keys = Keypair::generate();

    let mut output = File::create(key_path)?;
    output.write_all(&keys.expose_secret())?;
    set_permissions(&key_path, PermissionsExt::from_mode(0o600)).unwrap(); 

    let mut puboutput = File::create(pub_path)?;
    puboutput.write_all(&keys.public)?;
    print!("Enter password: ");
    std::io::stdout().flush()?;
    let password = read_password()?;
    let keymaterial = aesrest::derive_key(password.as_bytes(), 32);
    aesrest::encrypt_file(key_path, key_path, &keymaterial);

    Ok(())
}

fn verf(file_path: &str, pub_path: &str, sig_path: &str)  {
    let file_path = Path::new(file_path);
    let metadata = file_path.metadata().expect("Failed to read file metadata");
    let mut file = File::open(&file_path).expect("Failed to open the file");
    let mut bytes = Vec::new();

    file.read_to_end(&mut bytes).expect("Failed to read the file");

    let num_bytes = bytes.len();
    let num_bits = num_bytes * 8;
    let byte_distribution = bytes.iter().collect::<std::collections::HashSet<_>>().len() as f64 / num_bytes as f64;

    let file_is_open = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)
        {
            Ok(_) => false,
            Err(_) => true,
        };

    let chronox: String = Utc::now().to_string();
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    let mut resulto = hasher.finalize_xof();
    let mut shake256 = [0u8; 10];
    let _ = resulto.read(&mut shake256);
    println!("{{");
    println!("{:?}: {{", file_path);
    println!("  \"Checksum SHA3 SHAKE256 10\": \"{:?}\",", shake256);
    println!("  \"Report time\": \"{}\",", chronox.to_string());
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
    let created: DateTime<Utc> = DateTime::from(metadata.created().expect("Failed to get created timestamp."));
    let modified: DateTime<Utc> = DateTime::from(metadata.modified().expect("failed to get modified timestamp."));
    let access: DateTime<Utc> = DateTime::from(metadata.accessed().expect("failed to get accessed timestamp."));
    let changed: DateTime<Utc> = {
        let ctime = metadata.ctime();
        let ctimesec = metadata.ctime_nsec() as u32;
        let naive_datetime = NaiveDateTime::from_timestamp_opt(ctime, ctimesec).expect("Invalid changed timestamp");
        DateTime::<Utc>::from_utc(naive_datetime, Utc)
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

    let mut kfile = File::open(&pub_path).expect("Failed to open the key");
    let mut kbytes = Vec::new();
    kfile.read_to_end(&mut kbytes).expect("Failed to read the key");
    let mut sfile = File::open(&sig_path).expect("Failed to open the signature file");
    let mut sbytes = Vec::new();
    sfile.read_to_end(&mut sbytes).expect("Failed to read the key");

    let msg = &bytes;
    let sig_verify = verify(&sbytes, &msg, &kbytes);
    let statusig = sig_verify.is_ok();
    println!("  \"Verification Result\": \"{}\"", statusig);

    println!(" }}");
    println!("}}");

}

fn sig(file_path: &str, key_path: &str, pub_path: &str, sig_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    print!("Enter password: ");
    std::io::stdout().flush()?;
    let password = read_password()?;
    let keymaterial = aesrest::derive_key(password.as_bytes(), 32);

    aesrest::decrypt_file(key_path, key_path, &keymaterial);
    
    let file_path = Path::new(file_path);
    let metadata = file_path.metadata().expect("Failed to read file metadata");
    let mut file = File::open(&file_path).expect("Failed to open the file");
    let mut bytes = Vec::new();

    file.read_to_end(&mut bytes).expect("Failed to read the file");

    let num_bytes = bytes.len();
    let num_bits = num_bytes * 8;
    let byte_distribution = bytes.iter().collect::<std::collections::HashSet<_>>().len() as f64 / num_bytes as f64;

    let file_is_open = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)
        {
            Ok(_) => false,
            Err(_) => true,
        };

    let chronox: String = Utc::now().to_string();
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    let mut resulto = hasher.finalize_xof();
    let mut shake256 = [0u8; 10];
    let _ = resulto.read(&mut shake256);
    println!("{{");
    println!("{:?}: {{", file_path);
    println!("  \"Checksum SHA3 SHAKE256 10\": \"{:?}\",", shake256);
    println!("  \"Report time\": \"{}\",", chronox.to_string());
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
    let created: DateTime<Utc> = DateTime::from(metadata.created().expect("Failed to get created timestamp."));
    let modified: DateTime<Utc> = DateTime::from(metadata.modified().expect("failed to get modified timestamp."));
    let access: DateTime<Utc> = DateTime::from(metadata.accessed().expect("failed to get accessed timestamp."));
    let changed: DateTime<Utc> = {
        let ctime = metadata.ctime();
        let ctimesec = metadata.ctime_nsec() as u32;
        let naive_datetime = NaiveDateTime::from_timestamp_opt(ctime, ctimesec).expect("Invalid changed timestamp");
        DateTime::<Utc>::from_utc(naive_datetime, Utc)
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

    let kmetadata = keypath.metadata().expect("Failed to read file metadata for key");
    let mut kfile = File::open(&keypath).expect("Failed to open the key");
    let mut kpubf = File::open(&pubpath).expect("Failed to open the public key");

    let mut kbytes = Vec::new();
    kfile.read_to_end(&mut kbytes).expect("Failed to read the key");

    let mut pubbytes = Vec::new();
    kpubf.read_to_end(&mut pubbytes).expect("Failed to read the public key");

    let keys: Keypair = Keypair::loadit(pubbytes, kbytes);
    let msg = &bytes;
    let sig = keys.sign(&msg);
    let spath = Path::new(sig_path);
    let mut sigoutput = File::create(spath)?;
    sigoutput.write_all(&sig)?;
    println!("  \"Dilithium signature file\": \"{}\",", sig_path);
    println!("  \"Dilithium signing key\": \"{}\",", key_path);
    let kinode = kmetadata.ino();
    println!("  \"Key Inode\": \"{}\",", &kinode);
    let kcreated: DateTime<Utc> = DateTime::from(kmetadata.created().expect("Failed to get created timestamp."));
    let kmodified: DateTime<Utc> = DateTime::from(kmetadata.modified().expect("failed to get modified timestamp."));
    let kaccess: DateTime<Utc> = DateTime::from(kmetadata.accessed().expect("failed to get accessed timestamp."));
    let kchanged: DateTime<Utc> = {
        let ctime = kmetadata.ctime();
        let ctimesec = kmetadata.ctime_nsec() as u32;
        let naive_datetime = NaiveDateTime::from_timestamp_opt(ctime, ctimesec).expect("Invalid changed timestamp");
        DateTime::<Utc>::from_utc(naive_datetime, Utc)
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

    aesrest::encrypt_file(key_path, key_path, &keymaterial);
    
    Ok(())

}


fn donkout() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open("./wormsign.toml")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: Config = toml::from_str(&contents).unwrap();
    let args: Vec<String> = env::args().collect();
    let file_path = &config.file_path;
    let pub_path = &config.pub_path;
    let sig_path = &config.sig_path;
    let key_path = &config.key_path;
    for arg in args.iter() {
        match arg.as_str() {
            "-v"  => verf(file_path, pub_path, sig_path),
            "-g"  => keygen(key_path, pub_path)?,
            "-s"  => sig(file_path, key_path, pub_path, sig_path)?,
            _     => donkout()?
        }
    };
    Ok(())
}
