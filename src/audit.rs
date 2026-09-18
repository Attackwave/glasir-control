//! Enterprise Non-Blocking Audit & Request Logger.
//!
//! Every incoming request, its routing decision, response status, duration, and
//! data volume is recorded in a bounded background channel.
//!
//! **Enterprise Safety Guarantees:**
//! - **Never blocks a request:** If the queue fills or the filesystem stalls,
//!   records are dropped and counted rather than exhausting server memory or
//!   blocking client requests.
//! - **Strict file permissions (0600 on Unix):** Log contains user identities
//!   and repository names which must not be world-readable.
//! - **Bounded size & log rotation:** Automatically rotates at 10 MB, keeping
//!   one `.1` backup generation.
//! - **Optional signed hash chain:** an operator-provided key makes deletion,
//!   insertion and modification of records independently detectable.
//! - **Shared durable volumes:** writers serialize each append with an advisory
//!   lock and derive the predecessor from disk while holding it, so HA replicas
//!   cannot fork the signed chain on a lock-capable shared filesystem.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};

pub const DEFAULT_AUDIT_FILE: &str = "glasir-control-audit.jsonl";
const MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const QUEUE_CAPACITY: usize = 2048;

/// One audit log entry.
#[derive(Clone, Debug)]
pub struct Record {
    pub ts: u64,
    pub who: Option<String>,
    pub tree: Option<String>,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub bytes: usize,
    pub duration_ms: u64,
    pub client_addr: String,
}

pub struct Audit {
    path: PathBuf,
    tx: mpsc::SyncSender<Record>,
    dropped: Arc<AtomicU64>,
    remote_failed: Arc<AtomicU64>,
}

impl Audit {
    /// Starts the background audit writer thread.
    pub fn start(
        path: PathBuf,
        signing_key: Option<Vec<u8>>,
        remote_url: Option<String>,
        remote_key: Option<Vec<u8>>,
        remote_tls: Option<crate::backend_tls::BackendTls>,
    ) -> Audit {
        let (tx, rx) = mpsc::sync_channel::<Record>(QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let remote_failed = Arc::new(AtomicU64::new(0));
        let counter = dropped.clone();
        let remote_counter = remote_failed.clone();
        let writer_path = path.clone();

        std::thread::Builder::new()
            .name("glasir-audit-writer".into())
            .spawn(move || {
                let mut missed = 0u64;
                let mut previous_hmac = signing_key
                    .as_deref()
                    .and_then(|_| last_hmac(&writer_path))
                    .unwrap_or_default();
                for rec in rx {
                    let now = counter.swap(0, Ordering::Relaxed);
                    missed += now;
                    if let Ok(next_hmac) = write_record(
                        &writer_path,
                        &rec,
                        missed,
                        signing_key.as_deref(),
                        &previous_hmac,
                    ) {
                        if let Some(hmac) = next_hmac {
                            previous_hmac = hmac;
                        }
                        if let (Some(url), Some(key)) =
                            (remote_url.as_deref(), remote_key.as_deref())
                        {
                            let event = format_jsonl(&rec, missed);
                            let signature = crate::sync::hmac_sha256_hex(key, event.as_bytes());
                            let delivered = match remote_tls.as_ref() {
                                Some(tls) => crate::backend_tls::post(
                                    tls,
                                    url,
                                    &[
                                        ("Content-Type", "application/json".into()),
                                        ("X-Glasir-Audit-Signature", format!("sha256={signature}")),
                                    ],
                                    event.as_bytes(),
                                ),
                                None => ureq::post(url)
                                    .set("Content-Type", "application/json")
                                    .set("X-Glasir-Audit-Signature", &format!("sha256={signature}"))
                                    .send_string(&event)
                                    .map(|_| ())
                                    .map_err(std::io::Error::other),
                            };
                            if delivered.is_err() {
                                remote_counter.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        missed = 0;
                    }
                }
            })
            .expect("failed to spawn audit writer thread");

        Audit {
            path,
            tx,
            dropped,
            remote_failed,
        }
    }

    /// Records a request. Never blocks the caller; drops if queue is full.
    pub fn record(&self, rec: Record) {
        if self.tx.try_send(rec).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the number of dropped records so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn remote_failed(&self) -> u64 {
        self.remote_failed.load(Ordering::Relaxed)
    }

    /// Path to the current audit log file.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Appends a single record in JSONL format, rotating if needed.
fn write_record(
    path: &Path,
    rec: &Record,
    missed: u64,
    signing_key: Option<&[u8]>,
    _previous_hmac: &str,
) -> std::io::Result<Option<String>> {
    // Lock a separate stable inode rather than the audit file itself: rotation
    // renames the latter and would otherwise let a second writer lock a new
    // inode while the first one still owns the old lock.
    let lock_path = path.with_extension("audit.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    lock_exclusive(&lock)?;

    let result = write_record_locked(path, rec, missed, signing_key);
    let unlock_result = unlock(&lock);
    match result {
        Ok(value) => {
            unlock_result?;
            Ok(value)
        }
        Err(error) => {
            let _ = unlock_result;
            Err(error)
        }
    }
}

fn write_record_locked(
    path: &Path,
    rec: &Record,
    missed: u64,
    signing_key: Option<&[u8]>,
) -> std::io::Result<Option<String>> {
    if std::fs::metadata(path)
        .map(|m| m.len() >= MAX_BYTES)
        .unwrap_or(false)
    {
        let mut backup = path.to_path_buf();
        let ext = backup
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("jsonl");
        backup.set_extension(format!("{ext}.1"));
        let _ = std::fs::rename(path, backup);
    }

    let event = format_jsonl(rec, missed);
    let (json, next_hmac) = match signing_key {
        Some(key) => {
            // Do not trust a process-local predecessor: another replica may
            // have appended since this writer last emitted an event.
            let previous_hmac = last_hmac(path).unwrap_or_default();
            let message = format!("{previous_hmac}\n{event}");
            let hmac = crate::sync::hmac_sha256_hex(key, message.as_bytes());
            (
                format!(
                    "{{\"event\":{event},\"previous_hmac\":\"{previous_hmac}\",\"hmac\":\"{hmac}\"}}"
                ),
                Some(hmac),
            )
        }
        None => (event, None),
    };

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(path)?;
    writeln!(file, "{json}")?;
    file.flush()?;
    Ok(next_hmac)
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut backup = path.to_path_buf();
    let ext = backup
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("jsonl");
    backup.set_extension(format!("{ext}.1"));
    backup
}

fn last_hmac(path: &Path) -> Option<String> {
    // After rotation the predecessor is in `.jsonl.1` until the new current
    // segment receives its first event. Prefer current, then the backup.
    [path.to_path_buf(), rotated_path(path)]
        .into_iter()
        .find_map(|segment| {
            std::fs::read_to_string(segment)
                .ok()?
                .lines()
                .rev()
                .find_map(|line| {
                    serde_json::from_str::<serde_json::Value>(line)
                        .ok()?
                        .get("hmac")?
                        .as_str()
                        .filter(|hmac| {
                            hmac.len() == 64 && hmac.chars().all(|c| c.is_ascii_hexdigit())
                        })
                        .map(str::to_string)
                })
        })
}

#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(file), libc::LOCK_EX) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock(file: &std::fs::File) -> std::io::Result<()> {
    let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(file), libc::LOCK_UN) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn unlock(_: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

/// Verifies the signed current log and its one retained rotation segment.
/// An unsigned record, a missing record or any edited field fails validation.
pub fn verify(path: &Path, signing_key: &[u8]) -> Result<usize, String> {
    if signing_key.len() < 32 {
        return Err("audit signing key must contain at least 32 bytes".into());
    }
    let mut segments = Vec::new();
    let backup = rotated_path(path);
    if backup.exists() {
        segments.push(backup);
    }
    segments.push(path.to_path_buf());

    let mut previous = String::new();
    let mut count = 0;
    for segment in segments {
        let text = std::fs::read_to_string(&segment)
            .map_err(|error| format!("{}: {error}", segment.display()))?;
        for (line_no, line) in text.lines().enumerate() {
            let value: serde_json::Value = serde_json::from_str(line).map_err(|error| {
                format!(
                    "{}:{}: invalid JSON: {error}",
                    segment.display(),
                    line_no + 1
                )
            })?;
            let event = canonical_event(&value)
                .map_err(|error| format!("{}:{}: {error}", segment.display(), line_no + 1))?;
            let recorded_previous = value
                .get("previous_hmac")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "{}:{}: unsigned audit record",
                        segment.display(),
                        line_no + 1
                    )
                })?;
            let recorded_hmac = value
                .get("hmac")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "{}:{}: unsigned audit record",
                        segment.display(),
                        line_no + 1
                    )
                })?;
            if !crate::sync::constant_time_eq(recorded_previous.as_bytes(), previous.as_bytes()) {
                return Err(format!(
                    "{}:{}: audit chain discontinuity",
                    segment.display(),
                    line_no + 1
                ));
            }
            let expected = crate::sync::hmac_sha256_hex(
                signing_key,
                format!("{previous}\n{event}").as_bytes(),
            );
            if !crate::sync::constant_time_eq(recorded_hmac.as_bytes(), expected.as_bytes()) {
                return Err(format!(
                    "{}:{}: audit signature mismatch",
                    segment.display(),
                    line_no + 1
                ));
            }
            previous = recorded_hmac.to_string();
            count += 1;
        }
    }
    Ok(count)
}

/// Returns a bounded newest-first view for the administration timeline.
pub fn recent(path: &Path, limit: usize) -> Result<Vec<serde_json::Value>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    Ok(text
        .lines()
        .rev()
        .take(limit.min(200))
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

/// Appends a remotely exported canonical event after authenticating its HMAC.
/// Deploy this process with immutable/WORM storage; the lock makes concurrent
/// ingest replicas serialize each durable append.
pub fn append_remote_event(
    path: &Path,
    event: &[u8],
    signature: &str,
    key: &[u8],
) -> Result<(), String> {
    if event.len() > 1024 * 1024 {
        return Err("audit event exceeds 1 MiB".into());
    }
    let expected = format!("sha256={}", crate::sync::hmac_sha256_hex(key, event));
    if !crate::sync::constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        return Err("invalid audit signature".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(event).map_err(|_| "invalid audit JSON")?;
    if !value.is_object() {
        return Err("audit event must be an object".into());
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path.with_extension("ingest.lock"))
        .map_err(|e| e.to_string())?;
    lock_exclusive(&lock).map_err(|e| e.to_string())?;
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(event)?;
        file.write_all(b"\n")?;
        file.sync_data()
    })();
    let _ = unlock(&lock);
    result.map_err(|e| e.to_string())
}

fn canonical_event(entry: &serde_json::Value) -> Result<String, &'static str> {
    let event = entry
        .get("event")
        .and_then(serde_json::Value::as_object)
        .ok_or("missing event")?;
    let optional_string = |name| match event.get(name) {
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(serde_json::Value::Null) => Ok(None),
        _ => Err("invalid optional string field"),
    };
    let string = |name| {
        event
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or("missing string field")
    };
    let number = |name| {
        event
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing numeric field")
    };
    let status = number("status")?.try_into().map_err(|_| "invalid status")?;
    let bytes = number("bytes")?.try_into().map_err(|_| "invalid bytes")?;
    Ok(format_jsonl(
        &Record {
            ts: number("ts")?,
            who: optional_string("who")?,
            tree: optional_string("tree")?,
            method: string("method")?,
            path: string("path")?,
            status,
            bytes,
            duration_ms: number("duration_ms")?,
            client_addr: string("client_addr")?,
        },
        event
            .get("dropped_before")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    ))
}

/// Formats a record into clean, unescaped/escaped JSON.
fn format_jsonl(rec: &Record, missed: u64) -> String {
    let who_str = match &rec.who {
        Some(w) => format!("\"{}\"", escape_json(w)),
        None => "null".to_string(),
    };
    let tree_str = match &rec.tree {
        Some(t) => format!("\"{}\"", escape_json(t)),
        None => "null".to_string(),
    };
    let missed_str = if missed > 0 {
        format!(",\"dropped_before\":{missed}")
    } else {
        String::new()
    };

    format!(
        "{{\"ts\":{},\"who\":{},\"tree\":{},\"method\":\"{}\",\"path\":\"{}\",\"status\":{},\"bytes\":{},\"duration_ms\":{},\"client_addr\":\"{}\"{missed_str}}}",
        rec.ts,
        who_str,
        tree_str,
        escape_json(&rec.method),
        escape_json(&rec.path),
        rec.status,
        rec.bytes,
        rec.duration_ms,
        escape_json(&rec.client_addr),
    )
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_jsonl_renders_valid_json() {
        let rec = Record {
            ts: 1700000000,
            who: Some("anna".into()),
            tree: Some("alpha".into()),
            method: "POST".into(),
            path: "/mcp/alpha".into(),
            status: 200,
            bytes: 128,
            duration_ms: 12,
            client_addr: "127.0.0.1:45678".into(),
        };
        let json = format_jsonl(&rec, 0);
        assert!(json.contains("\"who\":\"anna\""));
        assert!(json.contains("\"tree\":\"alpha\""));
        assert!(json.contains("\"status\":200"));
        assert!(json.contains("\"duration_ms\":12"));
        assert!(!json.contains("dropped_before"));

        let json_with_drops = format_jsonl(&rec, 5);
        assert!(json_with_drops.contains("\"dropped_before\":5"));
    }

    #[test]
    fn null_fields_handled_cleanly() {
        let rec = Record {
            ts: 1700000000,
            who: None,
            tree: None,
            method: "GET".into(),
            path: "/health".into(),
            status: 200,
            bytes: 64,
            duration_ms: 1,
            client_addr: "127.0.0.1:12345".into(),
        };
        let json = format_jsonl(&rec, 0);
        assert!(json.contains("\"who\":null"));
        assert!(json.contains("\"tree\":null"));
        assert!(json.contains("\"path\":\"/health\""));
    }

    #[test]
    fn audit_file_writing_and_rotation() {
        let dir = std::env::temp_dir().join(format!("glasir_audit_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");

        let audit = Audit::start(path.clone(), None, None, None, None);
        for i in 0..10 {
            audit.record(Record {
                ts: 1700000000 + i,
                who: Some("test_user".into()),
                tree: Some("test_tree".into()),
                method: "POST".into(),
                path: "/mcp/test_tree".into(),
                status: 200,
                bytes: 100,
                duration_ms: 5,
                client_addr: "127.0.0.1:5000".into(),
            });
        }

        // Give worker thread a moment to flush
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 10);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signed_chain_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("glasir_audit_signed_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let key = b"0123456789abcdef0123456789abcdef";
        let record = Record {
            ts: 1700000000,
            who: Some("anna".into()),
            tree: Some("alpha".into()),
            method: "POST".into(),
            path: "/mcp/alpha".into(),
            status: 200,
            bytes: 1,
            duration_ms: 1,
            client_addr: "127.0.0.1:1".into(),
        };
        let first = write_record(&path, &record, 0, Some(key), "")
            .unwrap()
            .unwrap();
        write_record(&path, &record, 0, Some(key), &first).unwrap();
        assert_eq!(verify(&path, key).unwrap(), 2);
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"status\":200", "\"status\":201");
        std::fs::write(&path, edited).unwrap();
        assert!(verify(&path, key).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_ingest_requires_a_valid_signature_and_preserves_event() {
        let dir = std::env::temp_dir().join(format!(
            "glasir_audit_ingest_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let key = b"0123456789abcdef0123456789abcdef";
        let event = br#"{"ts":1,"who":"operator","path":"/policy"}"#;
        let signature = format!("sha256={}", crate::sync::hmac_sha256_hex(key, event));

        append_remote_event(&path, event, &signature, key).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            [event.as_slice(), b"\n"].concat()
        );
        assert!(append_remote_event(&path, event, "sha256=invalid", key).is_err());
        assert!(append_remote_event(&path, b"[]", &signature, key).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_writers_keep_one_signed_chain() {
        let dir = std::env::temp_dir().join(format!(
            "glasir_audit_concurrent_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let key = b"0123456789abcdef0123456789abcdef";
        let mut writers = Vec::new();
        for i in 0..16u64 {
            let path = path.clone();
            writers.push(std::thread::spawn(move || {
                write_record(
                    &path,
                    &Record {
                        ts: i,
                        who: Some(format!("writer-{i}")),
                        tree: Some("alpha".into()),
                        method: "POST".into(),
                        path: "/mcp/alpha".into(),
                        status: 200,
                        bytes: 1,
                        duration_ms: 1,
                        client_addr: "127.0.0.1:1".into(),
                    },
                    0,
                    Some(key),
                    "",
                )
                .unwrap();
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(verify(&path, key).unwrap(), 16);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
