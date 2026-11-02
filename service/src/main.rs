//! CoSign signing service: an mTLS API in front of the policy engine.
//!   POST /sign     withdrawal requests (safe, raw, authorization)     caller: sign
//!   POST /prices   signed price feed messages                         caller: sign
//!   POST /pause    pause every chain                                  caller: pause
//!   POST /unpause  resume every chain, needs a quorum of approvals    approver signatures
//!   GET  /health   pause state, license status, unpause challenge     any valid client cert
//! Run inside the enclave. The host should only forward TCP bytes (e.g. over vsock);
//! TLS terminates here, so the host cannot read or alter requests.

mod api;
mod config;
mod http;
mod tls;

use api::{err, Service};
use config::Config;
use cosign_policy::audit::{Entry, Sink, SinkError};
use cosign_policy::control::Secp256k1Verifier;
use cosign_policy::keccak::keccak256;
use cosign_policy::license::{hex, unhex};
use cosign_policy::signer::LocalKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, process::exit, thread};

type Svc = Service<LocalKey, FileSink, Secp256k1Verifier>;

/// Append-only audit file, fsynced per entry. Each process start writes a `# start`
/// marker and begins a new hash chain, because resuming a chain is not implemented.
/// In production point this at storage the host cannot rewrite (write-once, remote).
struct FileSink(File);

impl Sink for FileSink {
    fn append(&mut self, e: &Entry) -> Result<(), SinkError> {
        writeln!(self.0, "{} {} {} {} {}", e.seq, e.ts, hex(&e.prev), hex(&e.hash), e.detail).map_err(|_| SinkError)?;
        self.0.sync_data().map_err(|_| SinkError)
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Key as 64 hex characters in a file only the service user can read. In production,
/// replace this with a KMS-attested unseal that never writes the key to disk.
fn load_key(path: &str) -> Result<LocalKey, String> {
    let mode = fs::metadata(path).map_err(|e| format!("{path}: {e}"))?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!("{path}: key file must not be readable by group or others (chmod 600)"));
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let key: [u8; 32] = unhex(raw.trim())
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("{path}: expected 64 hex characters"))?;
    LocalKey::from_bytes(&key).map_err(|_| format!("{path}: invalid key"))
}

fn open_log(path: &str) -> Result<FileSink, String> {
    let mut f = OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("{path}: {e}"))?;
    writeln!(f, "# start {}", unix_now()).map_err(|e| format!("{path}: {e}"))?;
    Ok(FileSink(f))
}

fn serve(tcp: TcpStream, tls: &Arc<ServerConfig>, svc: &Mutex<Svc>) -> Option<()> {
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    tcp.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut stream = StreamOwned::new(ServerConnection::new(tls.clone()).ok()?, tcp);

    let reply = match http::read_request(&mut stream) {
        Ok(req) => {
            // The handshake has completed by now, so the client certificate is available.
            let der: &[u8] = stream.conn.peer_certificates()?.first()?.as_ref();
            let peer = hex(&keccak256(der));
            // A poisoned lock means a handler panicked mid-update: refuse everything.
            let mut s = svc.lock().ok()?;
            s.handle(&peer, &req.method, &req.path, &req.body, unix_now())
        }
        Err(code) => err(code, "bad request"),
    };
    http::write_response(&mut stream, reply.status, &reply.body).ok()
}

fn run(path: &str) -> Result<(), String> {
    let cfg: Config = serde_json::from_slice(&fs::read(path).map_err(|e| format!("{path}: {e}"))?)
        .map_err(|e| format!("config: {e}"))?;
    let service: Svc = Service::build(
        &cfg,
        Secp256k1Verifier,
        unix_now(),
        |c| load_key(&c.key_file),
        |c| open_log(&c.audit_log),
    )?;
    let tls = tls::server_config(&cfg.tls.cert, &cfg.tls.key, &cfg.tls.client_ca)?;
    let listener = TcpListener::bind(&cfg.listen).map_err(|e| format!("listen {}: {e}", cfg.listen))?;
    eprintln!("cosign-service listening on {} with {} chain(s)", cfg.listen, cfg.chains.len());

    let service = Arc::new(Mutex::new(service));
    for conn in listener.incoming() {
        let Ok(tcp) = conn else { continue };
        let (svc, tls) = (service.clone(), tls.clone());
        thread::spawn(move || {
            let _ = serve(tcp, &tls, &svc);
        });
    }
    Ok(())
}

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: cosign-service <config.json>");
        exit(2);
    };
    if let Err(e) = run(&path) {
        eprintln!("fatal: {e}");
        exit(1);
    }
}

