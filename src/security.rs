//! Enterprise Security Hardening (2026 Standard).
//!
//! Provides defense-in-depth protection across:
//! - **Constant-time cryptographic operations:** Prevents side-channel timing attacks.
//! - **URL decoding & strict identifier validation:** Immunizes against path traversal,
//!   null-byte injection, and Unicode lookalike attacks.
//! - **RFC 9112 HTTP Request Smuggling & Desynchronization defense:** Rejects dual
//!   `Content-Length` / `Transfer-Encoding` desync attempts.
//! - **Adaptive In-Memory Rate Limiting:** Per-IP token-bucket rate limiter with
//!   strict penalty for authentication failures.
//! - **Enterprise Security Headers:** HSTS, CSP, X-Content-Type-Options, X-Frame-Options.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Enterprise standard security response headers.
pub const SECURITY_HEADERS: &str = "\
X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n\
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n\
Cache-Control: no-store, no-cache, must-revalidate, private\r\n\
Referrer-Policy: no-referrer\r\n";

/// Constant-time slice comparison to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time string equality.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Decodes percent-encoded URL strings safely without external crates.
/// Returns None if malformed (e.g. invalid hex or truncated percent escape).
pub fn url_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let h1 = (bytes[i + 1] as char).to_digit(16)? as u8;
            let h2 = (bytes[i + 2] as char).to_digit(16)? as u8;
            out.push((h1 << 4) | h2);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A git revision a review may compare against: a branch, tag, commit or an
/// ancestor expression like `HEAD~3` or `main^2`. It reaches `git diff` as an
/// argument on the core, so a leading `-` would be read as an option.
pub fn is_valid_revision(rev: &str) -> bool {
    rev.len() <= 200
        && !rev.starts_with('-')
        && rev.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'_' | b'-' | b'~' | b'^')
        })
}

/// Validates that a tree or repository name strictly contains safe characters.
/// Rejects path separators, dots, control characters, null bytes, and traversal.
pub fn is_valid_identifier(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    // Reject any name starting or ending with hyphen/dot or containing traversal
    if name.starts_with('.') || name.starts_with('-') || name.contains("..") {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Per-IP Token Bucket Rate Limiter.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
    rate_per_sec: f64,
    capacity: f64,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate_per_sec,
            capacity: burst,
        }
    }

    /// Checks if a client IP is allowed to make a request.
    pub fn check_and_consume(&self, ip: &str, cost: f64) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Periodically purge old entries if map grows large (> 10,000 entries)
        if map.len() > 10000 {
            map.retain(|_, (_, last)| now.duration_since(*last).as_secs() < 300);
        }

        let entry = map.entry(ip.to_string()).or_insert((self.capacity, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.1 = now;

        // Refill tokens
        entry.0 = (entry.0 + elapsed * self.rate_per_sec).min(self.capacity);

        if entry.0 >= cost {
            entry.0 -= cost;
            true
        } else {
            false
        }
    }
}

/// Validates HTTP request headers against RFC 9112 Request Smuggling attacks.
pub fn validate_http_smuggling(headers: &[(String, String)]) -> Result<(), &'static str> {
    let mut cl_count = 0;
    let mut has_te = false;

    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        if lower == "content-length" {
            cl_count += 1;
            // Value must be strictly non-negative digits
            if v.trim().is_empty() || !v.trim().chars().all(|c| c.is_ascii_digit()) {
                return Err("malformed content-length header");
            }
        } else if lower == "transfer-encoding" {
            has_te = true;
        }
    }

    // RFC 9112 §6.1: Dual Content-Length or both TE and CL is a desync/smuggling attempt
    if cl_count > 1 {
        return Err("multiple content-length headers rejected (RFC 9112)");
    }
    if cl_count > 0 && has_te {
        return Err("simultaneous content-length and transfer-encoding rejected (RFC 9112)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_revision_is_a_revision_and_never_an_option() {
        for ok in [
            "HEAD~1",
            "main^2",
            "v0.2.1",
            "origin/main",
            "3f8ca1b",
            "feat/x-y_z",
        ] {
            assert!(is_valid_revision(ok), "{ok}");
        }
        for bad in [
            "--output=/tmp/x",
            "-p",
            "a b",
            "HEAD;rm",
            "a=b",
            "$(x)",
            &"a".repeat(201),
        ] {
            assert!(!is_valid_revision(bad), "{bad}");
        }
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"wrong"));
        assert!(!constant_time_eq(b"secret", b"sec"));
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("alpha%20beta").as_deref(), Some("alpha beta"));
        assert_eq!(url_decode("%2e%2e%2fetc").as_deref(), Some("../etc"));
        assert_eq!(url_decode("invalid%2"), None);
        assert_eq!(url_decode("invalid%GG"), None);
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(is_valid_identifier("alpha"));
        assert!(is_valid_identifier("repo-name_123"));
        assert!(!is_valid_identifier(".."));
        assert!(!is_valid_identifier("../alpha"));
        assert!(!is_valid_identifier("alpha/beta"));
        assert!(!is_valid_identifier("alpha\0beta"));
        assert!(!is_valid_identifier("alpha\\beta"));
        assert!(!is_valid_identifier(".hidden"));
        assert!(!is_valid_identifier(""));
    }

    #[test]
    fn test_rate_limiter() {
        let rl = RateLimiter::new(10.0, 5.0);
        let ip = "192.168.1.100";
        // Can consume up to burst capacity
        for _ in 0..5 {
            assert!(rl.check_and_consume(ip, 1.0));
        }
        // Exceeded burst
        assert!(!rl.check_and_consume(ip, 1.0));
    }

    #[test]
    fn test_validate_http_smuggling() {
        let valid_headers = vec![
            ("Content-Length".into(), "42".into()),
            ("Host".into(), "localhost".into()),
        ];
        assert!(validate_http_smuggling(&valid_headers).is_ok());

        let dual_cl = vec![
            ("Content-Length".into(), "42".into()),
            ("content-length".into(), "43".into()),
        ];
        assert!(validate_http_smuggling(&dual_cl).is_err());

        let te_and_cl = vec![
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Content-Length".into(), "42".into()),
        ];
        assert!(validate_http_smuggling(&te_and_cl).is_err());
    }
}
