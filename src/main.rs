//! glasir-control — the forwarding half of the control plane (stage 2 & stage 5).
//!
//! One address for many trees: authenticate the caller, decide which tree they
//! asked for, and hand the request to that tree's own `glasir serve`. Nothing
//! about the graph lives here — this service knows where a tree is and who may
//! see it, never what is in it.
//!
//! **Enterprise Safety & Operational Guarantees (2026 Standards):**
//! - **Separation via process boundary:** A tree a caller may not reach is never contacted.
//! - **Anti-oracle principle:** Forbidden and non-existent trees answer identically (404).
//! - **Credential isolation:** Caller tokens are stripped; proxy uses isolated backend tokens.
//! - **Constant-time crypto & timing-attack defense:** Constant-time hash verification.
//! - **URL normalization & strict identifier sanitization:** Defeats path traversal & null bytes.
//! - **RFC 9112 Request Smuggling defense:** Strict rejection of desync header combinations.
//! - **Adaptive Rate Limiting:** Per-IP token-bucket rate limiter with brute-force penalties.
//! - **Enterprise Security Headers:** HSTS, CSP, nosniff, and frame-deny on all responses.
//! - **Non-blocking audit logging:** Request metadata is queued to a bounded background logger.
//! - **Live hot-reloading:** Configuration and token changes take effect immediately without restarts.
//! - **Automated Code-Host Sync (Stage 5):** Webhook listeners for GitHub & GitLab with HMAC-SHA256 verification.
//! - **Observability:** Built-in `/health` health-check endpoint for orchestrators/load balancers.
//! - **Pre-flight config validation:** `--validate` CLI mode for CI/CD checks.

mod audit;
mod auth;
mod backend_tls;
mod crossrepo;
mod policy;
mod proxy;
mod rights;
mod security;
mod sync;

use audit::{Audit, Record as AuditRecord};
use proxy::Route;
use security::RateLimiter;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use sync::{SyncAction, SyncConfig};

const MAX_CONNECTIONS: usize = 64;
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
glasir-control — one address for many Glasir trees

USAGE
  glasir-control [OPTIONS]

OPTIONS
  --listen <addr>            Where to accept requests (default: 127.0.0.1:8800)
  --rights <file>            Trees and grants file (default: ./glasir-rights.tsv)
  --tokens <file>            Per-user tokens file (default: ./glasir.tokens)
  --audit <file>             Audit log destination (default: ./glasir-control-audit.jsonl)
  --audit-key-file <file>    ≥32-byte key for a signed, verifiable audit chain
  --audit-remote-url <url>   mTLS HTTPS append-only audit ingest endpoint
  --audit-remote-key-file <file> HMAC key for the external audit ingest
  --audit-remote-tls-ca <file> CA for mutually authenticated audit export
  --audit-remote-tls-cert <file> Audit-export client certificate
  --audit-remote-tls-key <file> Audit-export PKCS#8 client key
  --audit-ingest <addr>      Run a dedicated mTLS append-only audit ingest service
  --audit-ingest-store <file> Durable audit ingest JSONL destination
  --audit-ingest-key-file <file> HMAC key accepted by audit ingest
  --audit-ingest-tls-ca <file> CA for mandatory mTLS audit ingest clients
  --audit-ingest-tls-cert <file> Audit-ingest server certificate
  --audit-ingest-tls-key <file> Audit-ingest PKCS#8 server key
  --backend-tls-ca <file>    CA for mutually authenticated Core connections
  --backend-tls-cert <file>  Control-plane client certificate (PKCS#8 key required)
  --backend-tls-key <file>   Control-plane client private key
  --verify-audit <file>      Verify a signed audit log (requires --audit-key-file) and exit
  --access-review            Emit a deterministic, secret-free rights review JSON and exit
  --no-audit                 Disable audit logging
  --rate-limit <req/s>       Rate limit per client IP (default: 200)
  --allowed-origin <origin>  Exact browser Origin allowed to call this server
  --repo-map <file>          Explicit provider/repository-to-tree mapping for webhooks
  --sync-max-age <seconds>   Deny all tree access when mirrored rights are older
  --sync-interval <seconds> Full GitHub/GitLab reconciliation interval
  --github-token-env <name> Environment variable holding a GitHub API token
  --gitlab-token-env <name> Environment variable holding a GitLab API token
  --oidc-issuer <url>        OIDC issuer; enables RS256 JWT resource-server mode
  --oidc-audience <value>    Required JWT audience for this control plane
  --oidc-jwks <file>         Locally refreshed JWKS document for the issuer
  --oidc-subject-claim <key> JWT claim used as the rights identity (default: sub)
  --oidc-groups-claim <key>  JWT array claim mapped through `group` policy entries (default: groups)
  --oidc-client-id <id>      Public client for console single sign-on (Authorization Code + PKCE)
  --oidc-authorization-endpoint <url> The issuer's authorization endpoint, for console sign-on
  --oidc-token-endpoint <url> The issuer's token endpoint, for console sign-on
  --oidc-scope <scopes>      Scopes the console requests (default: openid)
  --github-secret <secret>   Webhook secret for GitHub HMAC-SHA256 signature verification
  --gitlab-secret <secret>   Webhook secret token for GitLab webhook verification
  --sync-grant <user>:<tree> Programmatically add user grant to rights file and exit
  --sync-revoke <user>:<tree>Programmatically revoke user grant from rights file and exit
  --validate                 Validate configuration files and exit
  --version, -v              Print version information
  --help, -h                 Print this help message

ENDPOINTS
  POST /mcp/<tree>                Forward MCP request to authorized tree
  GET  /trees                     List trees visible to the authenticated caller
  GET  /workspaces                List fully authorized cross-repository review workspaces
  GET  /api/admin/access-review   Administrator-only, secret-free access review
  GET  /api/admin/audit           Administrator-only recent audit timeline
  POST /api/review/impact         Run a bounded diff-impact review across an authorized workspace
  GET  /review, /admin            Browser console: impact review, access review, audit
                                 log, policy changes (token stays in tab memory)
  GET  /api/session              Who the credential belongs to, and whether it is admin
  GET  /api/sso                  Console sign-on settings (public client, no secret); 204 without them
  GET  /api/admin/policy/proposals  Administrator-only proposal list and active policy
  GET  /health                    Health check & system status for load balancers
  GET  /ready                     Readiness probe; fails closed on unusable identity or stale rights
  GET  /metrics                   Prometheus operational metrics
  POST /api/sync/webhook/github   GitHub webhook listener (member/collaborator events)
  POST /api/sync/webhook/gitlab   GitLab webhook listener (member events)
  GET  /api/sync/status           Code-host sync status
  GET  /api/workspaces/<name>/evidence  Authorized cross-repository contract evidence
";

struct Config {
    rights: rights::Watched,
    tokens: auth::Tokens,
    audit: Option<Audit>,
    sync: SyncConfig,
    rate_limiter: RateLimiter,
    start_time: Instant,
    active_conns: Arc<AtomicUsize>,
    allowed_origin: Option<String>,
    oidc: Option<auth::Oidc>,
    sso: Option<auth::Sso>,
    sync_max_age: Option<std::time::Duration>,
    sync_interval: Option<std::time::Duration>,
    backend_tls: Option<backend_tls::BackendTls>,
    cross_repo_evidence: Option<serde_json::Value>,
    policy_proposals: std::path::PathBuf,
}

fn main() -> std::io::Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    let val = |k: &str, d: &str| -> String {
        argv.iter()
            .position(|a| a == k)
            .and_then(|i| argv.get(i + 1))
            .cloned()
            .unwrap_or_else(|| d.to_string())
    };
    let opt_val = |k: &str| -> Option<String> {
        argv.iter()
            .position(|a| a == k)
            .and_then(|i| argv.get(i + 1))
            .cloned()
    };

    if let Some(addr) = opt_val("--audit-ingest") {
        let store = opt_val("--audit-ingest-store").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--audit-ingest-store is required",
            )
        })?;
        let key = opt_val("--audit-ingest-key-file").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--audit-ingest-key-file is required",
            )
        })?;
        let tls = match (
            opt_val("--audit-ingest-tls-ca"),
            opt_val("--audit-ingest-tls-cert"),
            opt_val("--audit-ingest-tls-key"),
        ) {
            (None, None, None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "audit ingest requires --audit-ingest-tls-ca, --audit-ingest-tls-cert and --audit-ingest-tls-key",
                ));
            }
            (Some(ca), Some(cert), Some(key)) => Some(backend_tls::load_server(&ca, &cert, &key)?),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--audit-ingest-tls-ca, --audit-ingest-tls-cert and --audit-ingest-tls-key must be supplied together",
                ));
            }
        };
        return run_audit_ingest(
            &addr,
            std::path::PathBuf::from(store),
            std::fs::read(key)?,
            tls,
        );
    }

    if argv.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return Ok(());
    }

    if argv.iter().any(|a| a == "--version" || a == "-v") {
        println!("glasir-control v{VERSION}");
        return Ok(());
    }

    let rights_path = val("--rights", "glasir-rights.tsv");
    let policy_proposals = val("--policy-proposals", "glasir-policy-proposals");
    let tokens_path = val("--tokens", "glasir.tokens");
    let audit_path = val("--audit", audit::DEFAULT_AUDIT_FILE);
    let cross_repo_evidence = opt_val("--cross-repo-evidence")
        .map(|path| {
            std::fs::read_to_string(path)
                .and_then(|text| serde_json::from_str(&text).map_err(std::io::Error::other))
        })
        .transpose()?;
    let no_audit = argv.iter().any(|a| a == "--no-audit");
    let audit_key = match opt_val("--audit-key-file") {
        Some(path) => {
            let key = std::fs::read(&path)?;
            if key.len() < 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--audit-key-file must contain at least 32 bytes",
                ));
            }
            Some(key)
        }
        None => None,
    };
    let audit_remote_url = opt_val("--audit-remote-url");
    let audit_remote_key = match opt_val("--audit-remote-key-file") {
        Some(path) => Some(std::fs::read(path)?),
        None => None,
    };
    if audit_remote_url.is_some() != audit_remote_key.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--audit-remote-url and --audit-remote-key-file must be supplied together",
        ));
    }
    let audit_remote_tls = match (
        opt_val("--audit-remote-tls-ca"),
        opt_val("--audit-remote-tls-cert"),
        opt_val("--audit-remote-tls-key"),
    ) {
        (None, None, None) if audit_remote_url.is_none() => None,
        (None, None, None) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--audit-remote-url requires --audit-remote-tls-ca, --audit-remote-tls-cert and --audit-remote-tls-key",
            ));
        }
        (Some(ca), Some(cert), Some(key)) if audit_remote_url.is_some() => {
            Some(backend_tls::load(&ca, &cert, &key)?)
        }
        (Some(_), Some(_), Some(_)) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "audit remote mTLS requires --audit-remote-url and --audit-remote-key-file",
            ));
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--audit-remote-tls-ca, --audit-remote-tls-cert and --audit-remote-tls-key must be supplied together",
            ));
        }
    };
    if let Some(path) = opt_val("--verify-audit") {
        let key = audit_key.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--verify-audit requires --audit-key-file",
            )
        })?;
        let count = audit::verify(std::path::Path::new(&path), key)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        println!("audit verified: {count} signed records");
        return Ok(());
    }
    if argv.iter().any(|arg| arg == "--access-review") {
        let text = std::fs::read_to_string(&rights_path)?;
        let validation = rights::validate_text(&text);
        if !validation.is_valid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "rights configuration is invalid: {}",
                    validation.errors.join("; ")
                ),
            ));
        }
        let json = serde_json::to_string_pretty(&rights::access_review(&rights::parse(&text)))
            .map_err(std::io::Error::other)?;
        println!("{json}");
        return Ok(());
    }
    let rate_limit: f64 = val("--rate-limit", "200.0").parse().unwrap_or(200.0);
    let backend_tls = match (
        opt_val("--backend-tls-ca"),
        opt_val("--backend-tls-cert"),
        opt_val("--backend-tls-key"),
    ) {
        (None, None, None) => None,
        (Some(ca), Some(cert), Some(key)) => Some(backend_tls::load(&ca, &cert, &key)?),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--backend-tls-ca, --backend-tls-cert and --backend-tls-key must be supplied together",
            ));
        }
    };
    let oidc = match (
        opt_val("--oidc-issuer"),
        opt_val("--oidc-audience"),
        opt_val("--oidc-jwks"),
    ) {
        (None, None, None) => None,
        (Some(issuer), Some(audience), Some(jwks)) => Some(auth::Oidc::new(
            issuer,
            audience,
            opt_val("--oidc-subject-claim").unwrap_or_else(|| "sub".into()),
            opt_val("--oidc-groups-claim").unwrap_or_else(|| "groups".into()),
            jwks.into(),
        )),
        _ => {
            eprintln!("--oidc-issuer, --oidc-audience and --oidc-jwks must be supplied together");
            std::process::exit(2);
        }
    };
    let sso = match (
        opt_val("--oidc-client-id"),
        opt_val("--oidc-authorization-endpoint"),
        opt_val("--oidc-token-endpoint"),
    ) {
        (None, None, None) => None,
        (Some(client_id), Some(authorization_endpoint), Some(token_endpoint)) if oidc.is_some() => {
            match auth::Sso::new(
                client_id,
                authorization_endpoint,
                token_endpoint,
                opt_val("--oidc-scope").unwrap_or_else(|| "openid".into()),
            ) {
                Ok(sso) => Some(sso),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            }
        }
        _ => {
            eprintln!(
                "--oidc-client-id, --oidc-authorization-endpoint and --oidc-token-endpoint must be supplied together, with --oidc-issuer"
            );
            std::process::exit(2);
        }
    };
    let sync_max_age = match opt_val("--sync-max-age") {
        Some(value) => match value.parse::<u64>() {
            Ok(0) | Err(_) => {
                eprintln!("--sync-max-age must be a positive number of seconds");
                std::process::exit(2);
            }
            Ok(seconds) => Some(std::time::Duration::from_secs(seconds)),
        },
        None => None,
    };
    let sync_interval = match opt_val("--sync-interval") {
        Some(value) => match value.parse::<u64>() {
            Ok(0) | Err(_) => {
                eprintln!("--sync-interval must be a positive number of seconds");
                std::process::exit(2);
            }
            Ok(seconds) => Some(std::time::Duration::from_secs(seconds)),
        },
        None => None,
    };

    // CLI Direct Permission Mutation Helpers
    if let Some(grant_spec) = opt_val("--sync-grant") {
        if let Some((user, tree)) = grant_spec.split_once(':') {
            sync::apply_sync_action(
                std::path::Path::new(&rights_path),
                &SyncAction::Grant {
                    user: user.to_string(),
                    tree: tree.to_string(),
                },
            )?;
            println!("granted: user '{user}' -> tree '{tree}' in {rights_path}");
            return Ok(());
        } else {
            eprintln!("error: --sync-grant requires <user>:<tree>");
            std::process::exit(1);
        }
    }

    if let Some(revoke_spec) = opt_val("--sync-revoke") {
        if let Some((user, tree)) = revoke_spec.split_once(':') {
            sync::apply_sync_action(
                std::path::Path::new(&rights_path),
                &SyncAction::Revoke {
                    user: user.to_string(),
                    tree: tree.to_string(),
                },
            )?;
            println!("revoked: user '{user}' -> tree '{tree}' in {rights_path}");
            return Ok(());
        } else {
            eprintln!("error: --sync-revoke requires <user>:<tree>");
            std::process::exit(1);
        }
    }

    // CLI Validation Mode
    if argv.iter().any(|a| a == "--validate") {
        return run_validation(&rights_path, &tokens_path);
    }

    let active_conns = Arc::new(AtomicUsize::new(0));
    let audit = if no_audit {
        None
    } else {
        Some(Audit::start(
            audit_path.into(),
            audit_key,
            audit_remote_url,
            audit_remote_key,
            audit_remote_tls,
        ))
    };

    let sync_cfg = SyncConfig {
        repo_mapping: match opt_val("--repo-map") {
            Some(path) => sync::load_repo_mapping(std::path::Path::new(&path))?,
            None => Default::default(),
        },
        github_secret: opt_val("--github-secret"),
        gitlab_secret: opt_val("--gitlab-secret"),
        github_token: opt_val("--github-token-env").and_then(|name| std::env::var(name).ok()),
        gitlab_token: opt_val("--gitlab-token-env").and_then(|name| std::env::var(name).ok()),
    };

    let cfg = Arc::new(Config {
        rights: rights::Watched::new(rights_path.into()),
        tokens: auth::Tokens::new(tokens_path.into()),
        audit,
        sync: sync_cfg,
        rate_limiter: RateLimiter::new(rate_limit, rate_limit * 2.0),
        start_time: Instant::now(),
        active_conns: active_conns.clone(),
        allowed_origin: opt_val("--allowed-origin"),
        oidc,
        sso,
        sync_max_age,
        sync_interval,
        backend_tls,
        cross_repo_evidence,
        policy_proposals: policy_proposals.into(),
    });

    // Enterprise safety refusal: never run without token credentials
    if cfg.oidc.is_none() && !cfg.tokens.configured() {
        eprintln!(
            "refusing to start with no tokens.\n\
             Every request would be anonymous, so no grant could be enforced.\n\
             Configure OIDC, or write one line per user to the tokens file: <sha256>\\t<name>\\t<expiry>"
        );
        std::process::exit(2);
    }

    if let Some(interval) = cfg.sync_interval {
        if cfg.sync.repo_mapping.is_empty() {
            eprintln!("--sync-interval requires at least one --repo-map entry");
            std::process::exit(2);
        }
        let reconcile = |cfg: &Config| {
            sync::reconcile_remote(
                cfg.rights.path(),
                &cfg.sync.repo_mapping,
                cfg.sync.github_token.as_deref(),
                cfg.sync.gitlab_token.as_deref(),
            )
        };
        // Establish a complete source-of-truth snapshot before serving. A
        // deployment that asks for periodic mirroring must never start from
        // an unverified, potentially stale rights file.
        if let Err(error) = reconcile(&cfg) {
            eprintln!("initial code-host reconciliation failed: {error}");
            std::process::exit(2);
        }
        let sync_cfg = cfg.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(interval);
                if let Err(error) = sync::reconcile_remote(
                    sync_cfg.rights.path(),
                    &sync_cfg.sync.repo_mapping,
                    sync_cfg.sync.github_token.as_deref(),
                    sync_cfg.sync.gitlab_token.as_deref(),
                ) {
                    eprintln!("code-host reconciliation failed: {error}");
                }
            }
        });
    }

    let listen = val("--listen", "127.0.0.1:8800");
    // Public TLS belongs at a reverse proxy. This process must never expose
    // bearer credentials directly over clear-text HTTP.
    if !is_loopback(&listen) {
        eprintln!(
            "refusing non-loopback control-plane bind. Terminate TLS at a reverse proxy and bind glasir-control to 127.0.0.1 or [::1]."
        );
        std::process::exit(2);
    }
    let listener = TcpListener::bind(&listen)?;
    let n = cfg.rights.current().trees.len();
    eprintln!("glasir-control v{VERSION}: listening on {listen}, {n} tree(s) configured");

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if active_conns.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            let mut s = stream;
            let _ = respond(
                &mut s,
                503,
                "503 Service Unavailable",
                "too many connections",
            );
            continue;
        }

        active_conns.fetch_add(1, Ordering::Relaxed);
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let _guard = Live(cfg.active_conns.clone());
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            if let Err(e) = handle(&cfg, stream) {
                eprintln!("control: {e}");
            }
        });
    }
    Ok(())
}

fn run_audit_ingest(
    addr: &str,
    store: std::path::PathBuf,
    key: Vec<u8>,
    tls: Option<backend_tls::ServerTls>,
) -> std::io::Result<()> {
    if key.len() < 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "audit ingest key must contain at least 32 bytes",
        ));
    }
    let listener = TcpListener::bind(addr)?;
    let active = Arc::new(AtomicUsize::new(0));
    eprintln!(
        "glasir audit-ingest: listening on {addr} ({})",
        if tls.is_some() {
            "mTLS required"
        } else {
            "HMAC only"
        }
    );
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("audit-ingest accept: {error}");
                continue;
            }
        };
        let store = store.clone();
        let key = key.clone();
        let tls = tls
            .as_ref()
            .map(|config| backend_tls::ServerTls(config.0.clone()));
        // The ingest has no reverse proxy in front of it. Bound handshake and
        // append workers so connection floods cannot turn into unbounded OS
        // threads before the mTLS verifier gets a chance to reject them.
        let active = active.clone();
        if active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_CONNECTIONS).then_some(count + 1)
            })
            .is_err()
        {
            continue;
        }
        std::thread::spawn(move || {
            let _guard = Live(active);
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            match tls {
                Some(config) => match backend_tls::accept(&config, stream) {
                    Ok(mut stream) => {
                        let _ = handle_audit_ingest_connection(&mut stream, &store, &key);
                    }
                    Err(error) => eprintln!("audit-ingest TLS: {error}"),
                },
                None => {
                    let mut stream = stream;
                    let _ = handle_audit_ingest_connection(&mut stream, &store, &key);
                }
            }
        });
    }
    Ok(())
}

fn handle_audit_ingest_connection<S: Read + Write>(
    stream: &mut S,
    store: &std::path::Path,
    key: &[u8],
) -> std::io::Result<()> {
    let request = proxy::read_request(&mut BufReader::new(&mut *stream))?;
    let result = match request {
        Some(req) if req.method == "POST" && req.path == "/v1/events" => req
            .header("x-glasir-audit-signature")
            .ok_or_else(|| "missing audit signature".to_string())
            .and_then(|signature| audit::append_remote_event(store, &req.body, signature, key)),
        _ => Err("invalid audit ingest request".to_string()),
    };
    match result {
        Ok(()) => respond_audit(stream, "204 No Content", ""),
        Err(_) => respond_audit(stream, "401 Unauthorized", "audit event rejected"),
    }
}

fn respond_audit<S: Write>(stream: &mut S, status: &str, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        security::SECURITY_HEADERS,
        body.len()
    )?;
    stream.flush()
}

fn run_validation(rights_path: &str, tokens_path: &str) -> std::io::Result<()> {
    println!("glasir-control: validating configuration...");
    let mut has_errors = false;

    // Validate rights file
    match rights::validate_file(std::path::Path::new(rights_path)) {
        Ok(rep) => {
            println!(
                "  [rights] {} — {} tree(s), {} user(s), {} role(s)",
                rights_path, rep.tree_count, rep.user_count, rep.role_count
            );
            for w in &rep.warnings {
                println!("    WARNING: {w}");
            }
            for e in &rep.errors {
                println!("    ERROR: {e}");
            }
            if !rep.is_valid() {
                has_errors = true;
            }
        }
        Err(e) => {
            println!("  [rights] {rights_path} — ERROR: could not read file: {e}");
            has_errors = true;
        }
    }

    // Validate tokens file
    match auth::validate_file(std::path::Path::new(tokens_path), auth::now()) {
        Ok(rep) => {
            println!(
                "  [tokens] {} — {} active, {} expired token(s)",
                tokens_path, rep.valid_count, rep.expired_count
            );
            for w in &rep.warnings {
                println!("    WARNING: {w}");
            }
            for e in &rep.errors {
                println!("    ERROR: {e}");
            }
            if !rep.is_valid() {
                has_errors = true;
            }
        }
        Err(e) => {
            println!("  [tokens] {tokens_path} — ERROR: could not read file: {e}");
            has_errors = true;
        }
    }

    if has_errors {
        eprintln!("\nConfiguration validation FAILED.");
        std::process::exit(1);
    } else {
        println!("\nConfiguration is VALID.");
        Ok(())
    }
}

/// Decrements active connection count when thread finishes.
struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn handle(cfg: &Config, mut stream: TcpStream) -> std::io::Result<()> {
    let start_ts = auth::now();
    let start_inst = Instant::now();
    let client_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let client_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Rate Limiting Protection (Token Bucket per IP)
    if !cfg.rate_limiter.check_and_consume(&client_ip, 1.0) {
        return too_many_requests(&mut stream);
    }

    let Some(req) = proxy::read_request(&mut BufReader::new(&stream))? else {
        return Ok(());
    };

    // A browser origin is accepted only when explicitly allowlisted. Native
    // MCP clients omit Origin and remain supported.
    if !origin_allowed(req.header("origin"), cfg.allowed_origin.as_deref()) {
        return respond(&mut stream, 403, "403 Forbidden", "origin not allowed");
    }

    // Health check endpoint (unauthenticated for orchestrators/k8s)
    if req.path == "/health" || req.path == "/healthz" {
        let uptime = cfg.start_time.elapsed().as_secs();
        let trees_count = cfg.rights.current().trees.len();
        let tokens_count = cfg.tokens.current().len();
        let active = cfg.active_conns.load(Ordering::Relaxed);
        let dropped_audit = cfg.audit.as_ref().map(|a| a.dropped()).unwrap_or(0);
        let remote_audit_failed = cfg.audit.as_ref().map(|a| a.remote_failed()).unwrap_or(0);

        let json = format!(
            "{{\"status\":\"ok\",\"version\":\"{}\",\"uptime_secs\":{},\"active_connections\":{},\"configured_trees\":{},\"configured_tokens\":{},\"audit_dropped\":{},\"audit_remote_failed\":{}}}",
            VERSION, uptime, active, trees_count, tokens_count, dropped_audit, remote_audit_failed
        );

        let bytes = json.len();
        let res = respond_json(&mut stream, 200, "200 OK", &json);

        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: None,
                tree: None,
                method: req.method,
                path: req.path,
                status: 200,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    // Liveness only says this process can answer. Readiness is deliberately
    // stricter: a load balancer must stop routing if the permission mirror has
    // expired or the configured identity source cannot admit a caller.
    if req.path == "/ready" {
        let mirror_fresh = cfg
            .sync_max_age
            .is_none_or(|max_age| cfg.rights.is_fresh(max_age));
        let identity_ready = cfg.oidc.is_some() || cfg.tokens.configured();
        let trees_ready = !cfg.rights.current().trees.is_empty();
        let ready = mirror_fresh && identity_ready && trees_ready;
        let status = if ready { 200 } else { 503 };
        let body = if ready {
            "{\"status\":\"ready\"}"
        } else {
            "{\"status\":\"not_ready\"}"
        };
        return respond_json(
            &mut stream,
            status,
            if ready {
                "200 OK"
            } else {
                "503 Service Unavailable"
            },
            body,
        );
    }

    // Kept small and cardinality-safe: no user, tree, URL or token labels.
    // The control plane is loopback-only, so an operator's collector reaches
    // this through the same authenticated network boundary as the proxy.
    if req.path == "/metrics" {
        let active = cfg.active_conns.load(Ordering::Relaxed);
        let trees = cfg.rights.current().trees.len();
        let dropped = cfg.audit.as_ref().map(|audit| audit.dropped()).unwrap_or(0);
        let remote_failed = cfg
            .audit
            .as_ref()
            .map(|audit| audit.remote_failed())
            .unwrap_or(0);
        let mirror_fresh = cfg
            .sync_max_age
            .is_none_or(|max_age| cfg.rights.is_fresh(max_age));
        let body = format!(
            "# TYPE glasir_control_active_connections gauge\n\
glasir_control_active_connections {active}\n\
# TYPE glasir_control_configured_trees gauge\n\
glasir_control_configured_trees {trees}\n\
# TYPE glasir_control_audit_dropped_total counter\n\
glasir_control_audit_dropped_total {dropped}\n\
# TYPE glasir_control_audit_remote_failed_total counter\n\
glasir_control_audit_remote_failed_total {remote_failed}\n\
# TYPE glasir_control_permission_mirror_fresh gauge\n\
glasir_control_permission_mirror_fresh {}\n",
            u8::from(mirror_fresh),
        );
        return respond_text(
            &mut stream,
            200,
            "200 OK",
            "text/plain; version=0.0.4",
            &body,
        );
    }

    // OPTIONS Pre-flight support
    if req.method == "OPTIONS" {
        return respond_options(&mut stream, cfg.allowed_origin.as_deref());
    }

    // GitHub Webhook Endpoint (Fail-Closed: strictly requires configured secret)
    if req.path == "/api/sync/webhook/github" && req.method == "POST" {
        let Some(secret) = &cfg.sync.github_secret else {
            return respond(
                &mut stream,
                403,
                "403 Forbidden",
                "github webhook secret not configured",
            );
        };

        let sig = req.header("x-hub-signature-256");
        if !sync::verify_github_signature(secret, &req.body, sig) {
            return respond(
                &mut stream,
                401,
                "401 Unauthorized",
                "invalid webhook signature",
            );
        }

        let event = req.header("x-github-event").unwrap_or("member");
        let payload = String::from_utf8_lossy(&req.body);

        if event == "pull_request" {
            let body = match sync::github_review_event(&payload) {
                Ok(Some(review)) => {
                    let repo_key = format!("github:{}", review.repository);
                    let rights = cfg.rights.current();
                    let result = cfg
                        .sync
                        .resolve_tree(&repo_key)
                        .and_then(|tree| {
                            rights
                                .unique_workspace_for_tree(&tree)
                                .map(|workspace| (tree, workspace))
                        })
                        .ok_or_else(|| {
                            "repository is not mapped to exactly one workspace".to_string()
                        })
                        .and_then(|(_, workspace)| {
                            provider_workspace_review(cfg, &rights, &workspace, &review.revision)
                        });
                    match result {
                        Ok(summary) => match cfg.sync.github_token.as_deref() {
                            Some(token) => match sync::github_check(&review.repository, &review.revision, &summary, token) {
                                Ok(()) => serde_json::json!({"status":"completed","workspace":summary}).to_string(),
                                Err(_) => "{\"status\":\"error\",\"message\":\"check publication failed\"}".to_string(),
                            },
                            None => "{\"status\":\"error\",\"message\":\"github token not configured\"}".to_string(),
                        },
                        Err(_) => "{\"status\":\"ignored\",\"message\":\"repository workspace mapping unavailable\"}".to_string(),
                    }
                }
                Ok(None) => "{\"status\":\"ignored\"}".to_string(),
                Err(_) => "{\"status\":\"error\",\"message\":\"malformed pull request payload\"}"
                    .to_string(),
            };
            return respond_json(&mut stream, 202, "202 Accepted", &body);
        }

        let (status_code, body) = match sync::handle_github_webhook(event, &payload, &cfg.sync) {
            Ok(Some(action)) => match sync::apply_sync_action(cfg.rights.path(), &action) {
                Ok(()) => (200, "{\"status\":\"ok\",\"applied\":true}"),
                Err(e) => {
                    eprintln!("sync: failed to update rights: {e}");
                    (
                        500,
                        "{\"status\":\"error\",\"message\":\"failed to update rights\"}",
                    )
                }
            },
            Ok(None) => (200, "{\"status\":\"ignored\"}"),
            Err(e) => {
                eprintln!("sync: webhook parse error: {e}");
                (
                    400,
                    "{\"status\":\"error\",\"message\":\"malformed payload\"}",
                )
            }
        };

        let res = respond_json(
            &mut stream,
            status_code,
            if status_code == 200 {
                "200 OK"
            } else {
                "400 Bad Request"
            },
            body,
        );
        return res;
    }

    // GitLab Webhook Endpoint (Fail-Closed: strictly requires configured secret)
    if req.path == "/api/sync/webhook/gitlab" && req.method == "POST" {
        let Some(secret) = &cfg.sync.gitlab_secret else {
            return respond(
                &mut stream,
                403,
                "403 Forbidden",
                "gitlab webhook secret not configured",
            );
        };

        let token = req.header("x-gitlab-token");
        if !sync::verify_gitlab_token(secret, token) {
            return respond(
                &mut stream,
                401,
                "401 Unauthorized",
                "invalid gitlab webhook token",
            );
        }

        let event = req.header("x-gitlab-event").unwrap_or("member");
        let payload = String::from_utf8_lossy(&req.body);

        if event == "Merge Request Hook" {
            let body = match sync::gitlab_review_event(&payload) {
                Ok(Some(review)) => {
                    let key = format!("gitlab:{}", review.repository);
                    let rights = cfg.rights.current();
                    let result = cfg
                        .sync
                        .resolve_tree(&key)
                        .and_then(|tree| {
                            rights
                                .unique_workspace_for_tree(&tree)
                                .map(|workspace| (tree, workspace))
                        })
                        .ok_or_else(|| {
                            "repository is not mapped to exactly one workspace".to_string()
                        })
                        .and_then(|(_, workspace)| {
                            provider_workspace_review(cfg, &rights, &workspace, &review.revision)
                        });
                    match (result, cfg.sync.gitlab_token.as_deref()) {
                        (Ok(summary), Some(token))
                            if sync::gitlab_commit_status(
                                &review.repository,
                                &review.revision,
                                &summary,
                                token,
                            )
                            .is_ok() =>
                        {
                            "{\"status\":\"completed\"}".to_string()
                        }
                        (Ok(_), None) => {
                            "{\"status\":\"error\",\"message\":\"gitlab token not configured\"}"
                                .to_string()
                        }
                        _ => "{\"status\":\"ignored\",\"message\":\"review unavailable\"}"
                            .to_string(),
                    }
                }
                Ok(None) => "{\"status\":\"ignored\"}".to_string(),
                Err(_) => "{\"status\":\"error\",\"message\":\"malformed merge request payload\"}"
                    .to_string(),
            };
            return respond_json(&mut stream, 202, "202 Accepted", &body);
        }

        let (status_code, body) = match sync::handle_gitlab_webhook(event, &payload, &cfg.sync) {
            Ok(Some(action)) => match sync::apply_sync_action(cfg.rights.path(), &action) {
                Ok(()) => (200, "{\"status\":\"ok\",\"applied\":true}"),
                Err(e) => {
                    eprintln!("sync: failed to update rights: {e}");
                    (
                        500,
                        "{\"status\":\"error\",\"message\":\"failed to update rights\"}",
                    )
                }
            },
            Ok(None) => (200, "{\"status\":\"ignored\"}"),
            Err(e) => {
                eprintln!("sync: webhook parse error: {e}");
                (
                    400,
                    "{\"status\":\"error\",\"message\":\"malformed payload\"}",
                )
            }
        };

        let res = respond_json(
            &mut stream,
            status_code,
            if status_code == 200 {
                "200 OK"
            } else {
                "400 Bad Request"
            },
            body,
        );
        return res;
    }

    // Sync Status Endpoint
    if req.path == "/api/sync/status" && req.method == "GET" {
        let has_gh = cfg.sync.github_secret.is_some();
        let has_gl = cfg.sync.gitlab_secret.is_some();
        let json = format!(
            "{{\"github_webhook_configured\":{},\"gitlab_webhook_configured\":{}}}",
            has_gh, has_gl
        );
        return respond_json(&mut stream, 200, "200 OK", &json);
    }

    let bearer = req
        .header("authorization")
        .and_then(|v| v.strip_prefix("Bearer "));
    // OIDC mode never falls back to static credentials: accepting both turns
    // the legacy token file into an unreviewed second authorization path.
    let identity = match &cfg.oidc {
        Some(oidc) => oidc.identify_with_groups(bearer),
        None => cfg
            .tokens
            .identify(bearer, auth::now())
            .map(|subject| auth::Identity {
                subject,
                groups: Vec::new(),
            }),
    };
    let who = identity.as_ref().map(|identity| identity.subject.clone());
    let groups = identity
        .as_ref()
        .map(|identity| identity.groups.as_slice())
        .unwrap_or(&[]);

    // A webhook is a delta, not proof that no event was missed. Deployments
    // that mirror a code host enable this lease and refresh rights.tsv from a
    // complete source-of-truth reconciliation before it expires.
    if let Some(max_age) = cfg.sync_max_age
        && !cfg.rights.is_fresh(max_age)
    {
        return respond(
            &mut stream,
            503,
            "503 Service Unavailable",
            "permission mirror is stale",
        );
    }

    // Penalize rate limit on failed authentication to thwart brute force
    if who.is_none() && req.header("authorization").is_some() {
        cfg.rate_limiter.check_and_consume(&client_ip, 5.0);
    }

    // One console answers both paths; the page opens the matching section.
    if (req.path == "/review" || req.path == "/admin") && req.method == "GET" {
        return respond_ui(
            &mut stream,
            "text/html; charset=utf-8",
            CONSOLE_HTML,
            cfg.sso.as_ref(),
        );
    }
    if req.path == "/console.css" && req.method == "GET" {
        return respond_ui(&mut stream, "text/css; charset=utf-8", CONSOLE_CSS, None);
    }
    if req.path == "/console.js" && req.method == "GET" {
        return respond_ui(
            &mut stream,
            "application/javascript; charset=utf-8",
            CONSOLE_JS,
            None,
        );
    }
    // The console's sign-on settings. A public client has no secret, so this
    // is answered before authentication, like the page itself.
    if req.path == "/api/sso" && req.method == "GET" {
        return match &cfg.sso {
            Some(sso) => respond_json(&mut stream, 200, "200 OK", &sso.public_json()),
            // No content rather than 404: the page asks on every load, and
            // a browser logs every 404 as an error.
            None => respond_json(&mut stream, 204, "204 No Content", ""),
        };
    }

    // Who the presented credential belongs to, so the console can greet the
    // user and show the administrator sections only to administrators.
    if req.path == "/api/session" && req.method == "GET" {
        let (status, bytes, res) = match &who {
            Some(user) => {
                let admin = cfg.rights.current().is_admin_with_groups(user, groups);
                let body = serde_json::json!({"user": user, "admin": admin}).to_string();
                let len = body.len();
                (200, len, respond_json(&mut stream, 200, "200 OK", &body))
            }
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    // The proposals an administrator can review, plus the active policy they
    // would replace. Administrators already read both through a single
    // proposal; the list only saves them knowing every ID by heart.
    if req.path == "/api/admin/policy/proposals" && req.method == "GET" {
        let (status, bytes, res) = match &who {
            Some(user) if cfg.rights.current().is_admin_with_groups(user, groups) => {
                match (
                    policy::list(&cfg.policy_proposals),
                    std::fs::read_to_string(cfg.rights.path()),
                ) {
                    (Ok(proposals), Ok(active)) => {
                        let body =
                            serde_json::json!({"proposals": proposals, "active_rights": active})
                                .to_string();
                        let len = body.len();
                        (200, len, respond_json(&mut stream, 200, "200 OK", &body))
                    }
                    _ => (
                        503,
                        21,
                        respond(
                            &mut stream,
                            503,
                            "503 Service Unavailable",
                            "proposals unavailable",
                        ),
                    ),
                }
            }
            Some(_) => (
                404,
                9,
                respond(&mut stream, 404, "404 Not Found", "not found"),
            ),
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    if req.path == "/api/review/impact" && req.method == "POST" {
        let (status, bytes, res) = match &who {
            Some(user) => {
                let input: serde_json::Value = match serde_json::from_slice(&req.body) {
                    Ok(value) => value,
                    Err(_) => {
                        return respond(
                            &mut stream,
                            400,
                            "400 Bad Request",
                            "invalid review request",
                        );
                    }
                };
                let workspace = input["workspace"]
                    .as_str()
                    .filter(|name| security::is_valid_identifier(name));
                let rev = input["rev"].as_str().unwrap_or("");
                let depth = input["depth"].as_u64().unwrap_or(3).clamp(1, 10);
                if !security::is_valid_revision(rev) {
                    return respond(&mut stream, 400, "400 Bad Request", "invalid revision");
                }
                let rights = cfg.rights.current();
                let Some((name, trees)) = workspace.and_then(|wanted| {
                    rights
                        .visible_workspaces(user, groups)
                        .into_iter()
                        .find(|(name, _)| name == wanted)
                }) else {
                    return respond(&mut stream, 404, "404 Not Found", "not found");
                };
                // One tool call on one tree of the workspace: its HTTP status
                // and JSON-RPC reply, or `None` when the tree is not answering.
                let call = |tree_name: &str, tool: &str, arguments: serde_json::Value| {
                    let tree = rights.tree(tree_name).expect("validated workspace tree");
                    let internal = proxy::Request {
                        method: "POST".into(),
                        path: "/mcp/internal".into(),
                        headers: Vec::new(),
                        body: serde_json::to_vec(&serde_json::json!({
                            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": tool, "arguments": arguments}
                        }))
                        .ok()?,
                    };
                    let reply = proxy::forward(tree, &internal, cfg.backend_tls.as_ref()).ok()?;
                    let status = proxy::extract_status(&reply);
                    let body = reply
                        .splitn(2, |byte| *byte == b'\n')
                        .last()
                        .unwrap_or(&reply);
                    let json_start = body.iter().position(|byte| *byte == b'{').unwrap_or(0);
                    let value: serde_json::Value = serde_json::from_slice(&body[json_start..])
                        .unwrap_or_else(|_| serde_json::json!({"error":"invalid core response"}));
                    Some((status, value))
                };
                let mut results = Vec::new();
                let mut changed = Vec::new();
                for tree_name in &trees {
                    match call(tree_name, "detect_changes", serde_json::json!({"rev": rev, "depth": depth})) {
                        Some((status, value)) => {
                            let symbols = value["result"]["structuredContent"]["changed_symbols"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|s| s.as_str().map(str::to_string))
                                .collect();
                            changed.push((tree_name.clone(), symbols));
                            results.push(serde_json::json!({"tree": tree_name, "status": status, "result": value}));
                        }
                        None => results.push(serde_json::json!({"tree": tree_name, "status": 502, "error":"tree is not answering"})),
                    }
                }
                // A client in one repository and its server in another: each
                // tree reports what it serves and requests, and the workspace
                // joins them. A Core without the tool reports nothing.
                let surfaces: Vec<(String, serde_json::Value)> = if trees.len() > 1 {
                    trees
                        .iter()
                        .filter_map(|t| {
                            let (_, value) = call(t, "http_surface", serde_json::json!({}))?;
                            Some((t.clone(), value["result"]["structuredContent"].clone()))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let links = crossrepo::links(&surfaces);
                let cross_repo_callers = crossrepo::callers_of_changes(&links, &changed);
                let packages = rights
                    .workspace_packages
                    .get(&name)
                    .cloned()
                    .unwrap_or_default();
                let evidence = cfg
                    .cross_repo_evidence
                    .as_ref()
                    .map(|report| workspace_evidence(report, &packages))
                    .unwrap_or_else(|| serde_json::json!({"edges":[],"unresolved":[]}));
                let body = serde_json::to_string(&serde_json::json!({"workspace": name, "rev": rev, "depth": depth, "repositories": results, "cross_repo_evidence": evidence, "cross_repo_routes": links.len(), "cross_repo_callers": cross_repo_callers})).map_err(std::io::Error::other)?;
                let len = body.len();
                (200, len, respond_json(&mut stream, 200, "200 OK", &body))
            }
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    // A workspace is an explicit repository set. It is deliberately visible
    // only when every member is individually authorized, preventing a partial
    // grant from becoming a repository-name oracle or a cross-repo escalation.
    if req.path == "/workspaces" && req.method == "GET" {
        let (status, body, res) = match &who {
            Some(user) => {
                let rights = cfg.rights.current();
                let entries: Vec<String> = rights
                    .visible_workspaces(user, groups)
                    .into_iter()
                    .map(|(name, trees)| {
                        format!(
                            "{{\"name\":{},\"trees\":[{}]}}",
                            json_string(&name),
                            trees
                                .iter()
                                .map(|tree| json_string(tree))
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    })
                    .collect();
                let body = format!("[{}]", entries.join(","));
                let result = respond_json(&mut stream, 200, "200 OK", &body);
                (200, body.len(), result)
            }
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes: body,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    // The UI consumes this same endpoint. A plain role named `admin` is an
    // explicit local policy decision, never inferred from a broad repository
    // grant or raw IdP group.
    if req.path == "/api/admin/access-review" && req.method == "GET" {
        let (status, bytes, res) = match &who {
            Some(user) => {
                let rights = cfg.rights.current();
                if rights.is_admin_with_groups(user, groups) {
                    let body = serde_json::to_string(&rights::access_review(&rights))
                        .map_err(std::io::Error::other)?;
                    let len = body.len();
                    (200, len, respond_json(&mut stream, 200, "200 OK", &body))
                } else {
                    (
                        404,
                        12,
                        respond(&mut stream, 404, "404 Not Found", "not found"),
                    )
                }
            }
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    if req.path == "/api/admin/audit" && req.method == "GET" {
        let (status, bytes, response) = match &who {
            Some(user) if cfg.rights.current().is_admin_with_groups(user, groups) => match cfg
                .audit
                .as_ref()
                .map(|audit| audit::recent(audit.path(), 100))
                .transpose()
            {
                Ok(Some(events)) => {
                    let body = serde_json::json!({"events":events}).to_string();
                    let bytes = body.len();
                    (200, bytes, respond_json(&mut stream, 200, "200 OK", &body))
                }
                Err(_) => (
                    503,
                    17,
                    respond(
                        &mut stream,
                        503,
                        "503 Service Unavailable",
                        "audit unavailable",
                    ),
                ),
                Ok(None) => (
                    503,
                    14,
                    respond(
                        &mut stream,
                        503,
                        "503 Service Unavailable",
                        "audit disabled",
                    ),
                ),
            },
            Some(_) => (
                404,
                9,
                respond(&mut stream, 404, "404 Not Found", "not found"),
            ),
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return response;
    }

    if req.path == "/api/admin/policy/proposals" && req.method == "POST" {
        let status = match &who {
            Some(user) if cfg.rights.current().is_admin_with_groups(user, groups) => {
                let input: serde_json::Value =
                    serde_json::from_slice(&req.body).unwrap_or_default();
                match (input["id"].as_str(), input["rights"].as_str()) {
                    (Some(id), Some(rights)) if security::is_valid_identifier(id) => {
                        match policy::create(
                            &cfg.policy_proposals,
                            id,
                            user,
                            rights,
                            cfg.rights.path(),
                        ) {
                            Ok(()) => 201,
                            Err(_) => 400,
                        }
                    }
                    _ => 400,
                }
            }
            Some(_) => 404,
            None => 401,
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes: if status == 201 { 20 } else { 23 },
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return if status == 201 {
            respond_json(&mut stream, 201, "201 Created", "{\"status\":\"pending\"}")
        } else if status == 401 {
            unauthorized(&mut stream)
        } else {
            respond(
                &mut stream,
                status,
                if status == 404 {
                    "404 Not Found"
                } else {
                    "400 Bad Request"
                },
                "policy proposal rejected",
            )
        };
    }

    if let Some(id) = req.path.strip_prefix("/api/admin/policy/proposals/")
        && req.method == "GET"
        && security::is_valid_identifier(id)
    {
        let (status, bytes, response) = match &who {
            Some(user) if cfg.rights.current().is_admin_with_groups(user, groups) => {
                match policy::read(&cfg.policy_proposals, id, cfg.rights.path()) {
                    Ok(value) => {
                        let body = value.to_string();
                        let bytes = body.len();
                        (200, bytes, respond_json(&mut stream, 200, "200 OK", &body))
                    }
                    Err(_) => (
                        404,
                        9,
                        respond(&mut stream, 404, "404 Not Found", "not found"),
                    ),
                }
            }
            Some(_) => (
                404,
                9,
                respond(&mut stream, 404, "404 Not Found", "not found"),
            ),
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return response;
    }

    if let Some(id) = req
        .path
        .strip_prefix("/api/admin/policy/proposals/")
        .and_then(|path| path.strip_suffix("/approve"))
        && req.method == "POST"
    {
        let status = match &who {
            Some(user)
                if cfg.rights.current().is_admin_with_groups(user, groups)
                    && security::is_valid_identifier(id) =>
            {
                match policy::approve(&cfg.policy_proposals, id, user, cfg.rights.path()) {
                    Ok(()) => 200,
                    Err(_) => 400,
                }
            }
            Some(_) => 404,
            None => 401,
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes: if status == 200 { 21 } else { 24 },
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return if status == 200 {
            respond_json(&mut stream, 200, "200 OK", "{\"status\":\"approved\"}")
        } else if status == 401 {
            unauthorized(&mut stream)
        } else {
            respond(
                &mut stream,
                status,
                if status == 404 {
                    "404 Not Found"
                } else {
                    "400 Bad Request"
                },
                "policy approval rejected",
            )
        };
    }

    if req.path == "/api/cross-repo/evidence" && req.method == "GET" {
        let (status, bytes, res) = match &who {
            Some(user) if cfg.rights.current().is_admin_with_groups(user, groups) => {
                match &cfg.cross_repo_evidence {
                    Some(value) => {
                        let body = value.to_string();
                        let bytes = body.len();
                        (200, bytes, respond_json(&mut stream, 200, "200 OK", &body))
                    }
                    None => (
                        503,
                        20,
                        respond(
                            &mut stream,
                            503,
                            "503 Service Unavailable",
                            "evidence unavailable",
                        ),
                    ),
                }
            }
            Some(_) => (
                404,
                12,
                respond(&mut stream, 404, "404 Not Found", "not found"),
            ),
            None => (401, 34, unauthorized(&mut stream)),
        };
        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status,
                bytes,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    // List visible trees for caller
    if req.path == "/trees" {
        let (status_code, body_len, res) = match &who {
            Some(user) => {
                let rights = cfg.rights.current();
                let list: Vec<String> = rights
                    .trees
                    .iter()
                    .filter(|tree| rights.may_with_groups(user, groups, &tree.name))
                    .map(|t| format!("{{\"name\":\"{}\"}}", t.name))
                    .collect();
                let json = format!("[{}]", list.join(","));
                let len = json.len();
                (200, len, respond_json(&mut stream, 200, "200 OK", &json))
            }
            None => (401, 34, unauthorized(&mut stream)),
        };

        if let Some(audit) = &cfg.audit {
            audit.record(AuditRecord {
                ts: start_ts,
                who: who.clone(),
                tree: None,
                method: req.method,
                path: req.path,
                status: status_code,
                bytes: body_len,
                duration_ms: start_inst.elapsed().as_millis() as u64,
                client_addr,
            });
        }
        return res;
    }

    let target_tree = proxy::tree_of(&req.path);
    let tool = mcp_tool_name(&req);
    let rights = cfg.rights.current();
    let route = proxy::route(&rights, who.as_deref(), &req.path);
    let (status_code, bytes_sent, res) = match route {
        Route::Unauthenticated => (401, 34, unauthorized(&mut stream)),
        Route::NotFound => (
            404,
            12,
            respond(&mut stream, 404, "404 Not Found", "no such tree"),
        ),
        Route::To(_tree)
            if who
                .as_deref()
                .zip(target_tree.as_deref())
                .zip(tool.as_deref())
                .is_some_and(|((user, tree_name), tool_name)| {
                    !rights.may_tool_with_groups(user, groups, tree_name, tool_name)
                }) =>
        {
            (
                403,
                20,
                respond(&mut stream, 403, "403 Forbidden", "tool not permitted"),
            )
        }
        Route::To(tree) => match proxy::forward(&tree, &req, cfg.backend_tls.as_ref()) {
            Ok(reply) => {
                let status = proxy::extract_status(&reply);
                let len = reply.len();
                let send_res = stream.write_all(&reply).and_then(|()| stream.flush());
                (status, len, send_res)
            }
            Err(e) => {
                eprintln!("control: {} unreachable: {e}", tree.name);
                (
                    502,
                    21,
                    respond(&mut stream, 502, "502 Bad Gateway", "tree is not answering"),
                )
            }
        },
    };

    if let Some(audit) = &cfg.audit {
        audit.record(AuditRecord {
            ts: start_ts,
            who,
            tree: target_tree,
            method: req.method,
            path: req.path,
            status: status_code,
            bytes: bytes_sent,
            duration_ms: start_inst.elapsed().as_millis() as u64,
            client_addr,
        });
    }

    res
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization cannot fail")
}

fn workspace_evidence(report: &serde_json::Value, packages: &[String]) -> serde_json::Value {
    let allowed = |value: &serde_json::Value| {
        value
            .as_str()
            .is_some_and(|name| packages.iter().any(|package| package == name))
    };
    let edges: Vec<_> = report["edges"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|edge| allowed(&edge["source"]) && allowed(&edge["target"]))
        .cloned()
        .collect();
    let unresolved: Vec<_> = report["unresolved"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry
                .as_str()
                .is_some_and(|text| packages.iter().any(|package| text.starts_with(package)))
        })
        .cloned()
        .collect();
    serde_json::json!({"schema":"glasir.cross-repo-report.v1", "edges":edges, "unresolved":unresolved})
}

/// Provider automation has no end-user identity. Its authority is therefore
/// narrower than `/api/review/impact`: a signed provider event, explicit
/// repository mapping and exactly one workspace are all required upstream.
fn provider_workspace_review(
    cfg: &Config,
    rights: &rights::Rights,
    workspace: &str,
    rev: &str,
) -> Result<String, String> {
    let trees = rights
        .workspaces
        .get(workspace)
        .ok_or("unknown workspace")?;
    if !security::is_valid_revision(rev) {
        return Err("invalid revision".into());
    }
    let request = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"detect_changes","arguments":{"rev":rev,"depth":3}}})).map_err(|e| e.to_string())?;
    let mut lines = vec![format!("Workspace `{workspace}` — revision `{rev}`")];
    for name in trees {
        let tree = rights
            .tree(name)
            .ok_or("workspace references unknown tree")?;
        let req = proxy::Request {
            method: "POST".into(),
            path: "/mcp/internal".into(),
            headers: Vec::new(),
            body: request.clone(),
        };
        match proxy::forward(tree, &req, cfg.backend_tls.as_ref()) {
            Ok(reply) if proxy::extract_status(&reply) < 400 => {
                lines.push(format!("- `{name}`: impact analyzed"))
            }
            Ok(reply) => lines.push(format!(
                "- `{name}`: Core returned HTTP {}",
                proxy::extract_status(&reply)
            )),
            Err(_) => lines.push(format!("- `{name}`: unavailable")),
        }
    }
    let packages = rights
        .workspace_packages
        .get(workspace)
        .cloned()
        .unwrap_or_default();
    let evidence = cfg
        .cross_repo_evidence
        .as_ref()
        .map(|report| workspace_evidence(report, &packages))
        .unwrap_or_else(|| serde_json::json!({"edges":[],"unresolved":[]}));
    lines.push(format!(
        "- contract edges: {}; unresolved contracts: {}",
        evidence["edges"].as_array().map_or(0, Vec::len),
        evidence["unresolved"].as_array().map_or(0, Vec::len)
    ));
    Ok(lines.join("\n"))
}

const CONSOLE_HTML: &str = include_str!("../assets/console.html");
const CONSOLE_CSS: &str = include_str!("../assets/console.css");
const CONSOLE_JS: &str = include_str!("../assets/console.js");

fn respond_ui(
    stream: &mut TcpStream,
    content_type: &str,
    body: &str,
    sso: Option<&auth::Sso>,
) -> std::io::Result<()> {
    // The page redeems its sign-on code at the issuer's token endpoint, so
    // that one origin, and no other, joins connect-src.
    let token_origin = sso.map_or(String::new(), |sso| format!(" {}", sso.token_origin));
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'{token_origin}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

/// Extracts the MCP tool name only from a well-formed `tools/call`. Requests
/// that are not a tool invocation remain the Core's protocol responsibility;
/// a policy can only constrain a name the proxy can establish unambiguously.
fn mcp_tool_name(req: &proxy::Request) -> Option<String> {
    if req.method != "POST" || !req.path.starts_with("/mcp/") {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&req.body).ok()?;
    (value.get("method")?.as_str()? == "tools/call").then(|| {
        value
            .get("params")?
            .get("name")?
            .as_str()
            .map(str::to_string)
    })?
}

/// A standard-compliant 401 with WWW-Authenticate per RFC 6750 & RFC 9728 and Enterprise Security Headers.
fn unauthorized(stream: &mut TcpStream) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 401 Unauthorized\r\n\
         Content-Type: text/plain\r\n\
         WWW-Authenticate: Bearer realm=\"glasir-control\", error=\"invalid_token\", error_description=\"bad, expired or missing credential\"\r\n\
         {}\
         Content-Length: 34\r\n\
         Connection: close\r\n\r\n\
         bad, expired or missing credential",
        security::SECURITY_HEADERS
    )?;
    stream.flush()
}

/// A 429 Too Many Requests response.
fn too_many_requests(stream: &mut TcpStream) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 429 Too Many Requests\r\n\
         Content-Type: text/plain\r\n\
         Retry-After: 1\r\n\
         {}\
         Content-Length: 20\r\n\
         Connection: close\r\n\r\n\
         rate limit exceeded\n",
        security::SECURITY_HEADERS
    )?;
    stream.flush()
}

fn respond(stream: &mut TcpStream, _code: u16, status: &str, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain\r\n\
         {}\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        security::SECURITY_HEADERS,
        body.len()
    )?;
    stream.flush()
}

fn respond_options(stream: &mut TcpStream, allowed_origin: Option<&str>) -> std::io::Result<()> {
    let cors = allowed_origin
        .map(|origin| format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "HTTP/1.1 204 No Content\r\n\
         Allow: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Authorization, Content-Type, X-Hub-Signature-256, X-Gitlab-Token\r\n\
         {}{}\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
        cors,
        security::SECURITY_HEADERS
    )?;
    stream.flush()
}

fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr.starts_with("localhost:") || addr.starts_with("[::1]")
}

fn origin_allowed(origin: Option<&str>, allowed: Option<&str>) -> bool {
    match origin {
        None => true,
        Some(origin) => allowed.is_some_and(|value| value == origin),
    }
}

fn respond_json(
    stream: &mut TcpStream,
    _code: u16,
    status: &str,
    body: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         {}\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        security::SECURITY_HEADERS,
        body.len()
    )?;
    stream.flush()
}

fn respond_text(
    stream: &mut TcpStream,
    _code: u16,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         {}\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        security::SECURITY_HEADERS,
        body.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::route;
    use crate::rights::{Rights, Tree};

    fn fixture() -> Rights {
        rights::parse(
            "# comment\n\
             tree\talpha\t127.0.0.1:7001\tsecret-a\n\
             tree\tbeta\t127.0.0.1:7002\tsecret-b\n\
             grant\tanna\talpha\n\
             grant\tbruno\talpha,beta\n\
             this line is malformed\n",
        )
    }

    #[test]
    fn a_tree_you_may_not_reach_looks_like_one_that_is_not_there() {
        let r = fixture();
        assert_eq!(route(&r, Some("anna"), "/mcp/beta"), Route::NotFound);
        assert_eq!(route(&r, Some("anna"), "/mcp/gamma"), Route::NotFound);
        assert!(matches!(
            route(&r, Some("anna"), "/mcp/alpha"),
            Route::To(_)
        ));
    }

    #[test]
    fn no_credential_is_not_a_missing_tree() {
        assert_eq!(
            route(&fixture(), None, "/mcp/alpha"),
            Route::Unauthenticated
        );
    }

    #[test]
    fn a_malformed_line_grants_nothing() {
        let r = fixture();
        assert_eq!(
            r.trees.len(),
            2,
            "the malformed line is skipped, not parsed"
        );
        assert!(!r.may("this", "line"));
    }

    #[test]
    fn a_path_cannot_climb_out_of_the_namespace() {
        assert_eq!(proxy::tree_of("/mcp/alpha").as_deref(), Some("alpha"));
        assert_eq!(proxy::tree_of("/mcp/alpha/extra").as_deref(), Some("alpha"));
        assert_eq!(proxy::tree_of("/mcp/../etc"), None);
        assert_eq!(proxy::tree_of("/mcp/%2e%2e%2fetc"), None);
        assert_eq!(proxy::tree_of("/mcp/"), None);
        assert_eq!(proxy::tree_of("/mcp"), None);
        assert_eq!(proxy::tree_of("/other"), None);
    }

    #[test]
    fn visible_lists_only_what_was_granted() {
        let r = fixture();
        let names: Vec<&str> = r.visible("anna").iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["alpha"], "beta must not appear at all");
        assert_eq!(r.visible("bruno").len(), 2);
        assert!(r.visible("nobody").is_empty());
    }

    #[test]
    fn a_granted_but_unconfigured_tree_is_not_found() {
        let r = rights::parse("grant\tanna\tghost\n");
        assert_eq!(route(&r, Some("anna"), "/mcp/ghost"), Route::NotFound);
    }

    #[test]
    fn the_caller_credential_is_never_forwarded() {
        let tree = Tree {
            name: "alpha".into(),
            addr: "127.0.0.1:7001".into(),
            token: "backend-secret".into(),
        };
        let req = proxy::Request {
            method: "POST".into(),
            path: "/mcp/alpha".into(),
            headers: vec![
                ("Authorization".into(), "Bearer caller-secret".into()),
                ("Origin".into(), "https://glasir.example.com".into()),
            ],
            body: b"{}".to_vec(),
        };
        let head = proxy::backend_head(&tree, &req);
        assert!(
            !head.contains("caller-secret"),
            "the caller's credential must not reach the backend:\n{head}"
        );
        assert!(
            head.contains("Authorization: Bearer backend-secret"),
            "and ours must, or the backend refuses us:\n{head}"
        );
        assert!(head.contains("Content-Length: 2"), "{head}");
        assert!(head.contains("Host: 127.0.0.1:7001"), "{head}");
        assert!(
            !head.to_ascii_lowercase().contains("origin:"),
            "the browser Origin must not cross the data-plane boundary: {head}"
        );
    }
}
