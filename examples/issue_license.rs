//! Offline license issuer. Run it on a machine you control and keep the key out of
//! every customer build; customers only ever get the signed token and the PUBLIC key.
//!
//!   cargo run --features k256 --example issue_license -- keygen issuer.key
//!   cargo run --features k256 --example issue_license -- issue issuer.key acme.lic \
//!       --licensee "Acme Exchange" --plan Exchange --max-chains unlimited \
//!       --features mpc-adapters --platforms acme.example --days 365
//!
//! Unix only (reads /dev/urandom, writes the key file with mode 0600).

use cosign_policy::keccak::keccak256;
use cosign_policy::license::{hex, unhex, License};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, process::exit};

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(1)
}

fn signing_key(bytes: &[u8]) -> SigningKey {
    SigningKey::from_bytes(k256::FieldBytes::from_slice(bytes)).unwrap_or_else(|_| die("invalid key"))
}

fn keygen(path: &str) {
    let mut b = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .unwrap_or_else(|_| die("no randomness source"));
    let sk = signing_key(&b);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| die("cannot create key file (does it already exist?)"));
    f.write_all(hex(&b).as_bytes()).unwrap_or_else(|_| die("cannot write key file"));
    println!("issuer public key (embed this in the enclave build):");
    println!("{}", hex(sk.verifying_key().to_encoded_point(true).as_bytes()));
}

fn issue(key_path: &str, out: &str, args: &[String]) {
    let mut o: HashMap<&str, &str> = HashMap::new();
    for pair in args.chunks(2) {
        match pair {
            [k, v] => o.insert(k.trim_start_matches("--"), v.as_str()),
            _ => die("arguments must be --name value pairs"),
        };
    }
    let opt = |k: &str| o.get(k).copied().unwrap_or("");
    let req = |k: &str| o.get(k).copied().unwrap_or_else(|| die(&format!("missing --{k}")));
    let list = |s: &str| if s.is_empty() { Vec::new() } else { s.split(',').map(String::from).collect::<Vec<_>>() };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days: u64 = req("days").parse().unwrap_or_else(|_| die("bad --days"));
    let lic = License {
        licensee: req("licensee").into(),
        plan: req("plan").into(),
        max_chains: match req("max-chains") {
            "unlimited" => u32::MAX,
            n => n.parse().unwrap_or_else(|_| die("bad --max-chains")),
        },
        features: list(opt("features")),
        platforms: list(opt("platforms")),
        issued_at: now,
        expires_at: now + days * 86_400,
    };
    let payload = lic.payload().unwrap_or_else(|| die("invalid license fields"));

    let raw = fs::read_to_string(key_path).unwrap_or_else(|_| die("cannot read key file"));
    let key = unhex(raw.trim()).filter(|b| b.len() == 32).unwrap_or_else(|| die("bad key file"));
    let sig: Signature =
        signing_key(&key).sign_prehash(&keccak256(payload.as_bytes())).unwrap_or_else(|_| die("signing failed"));

    fs::write(out, format!("{payload}sig={}\n", hex(&sig.to_bytes()))).unwrap_or_else(|_| die("cannot write license"));
    println!("wrote {out}");
}

fn main() {
    let a: Vec<String> = env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("keygen") if a.len() == 2 => keygen(&a[1]),
        Some("issue") if a.len() >= 3 => issue(&a[1], &a[2], &a[3..]),
        _ => die("usage: keygen <key-file> | issue <key-file> <out-file> --licensee X --plan P --max-chains N|unlimited [--features a,b] [--platforms x,y] --days N"),
    }
}
