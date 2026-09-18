//! Who is asking: the core's token file, read by a second process.
//!
//! Deliberately the same format as `glasir`'s `.glasir-tokens`
//! (`<sha256>\t<name>\t<expiry>`), so an operator has one thing to learn and
//! stage 4 replaces only who *writes* it. Reading is identical: compare
//! hashes, honour the expiry, re-read when the mtime moves so a revocation
//! takes effect without a restart.
//!
//! **The SHA-256 below is a deliberate copy, not accidental duplication.** The
//! two repositories share no code on purpose — that boundary is what keeps a
//! web framework and a session store out of the core — and a shared crate just
//! to avoid fifty lines of fully specified arithmetic would reintroduce the
//! coupling the split exists to prevent. It is verified against the published
//! FIPS 180-4 vectors here as well, because a hash that merely looks plausible
//! makes every credential comparison silently wrong.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub hash: String,
    pub name: String,
    /// Unix seconds, or 0 for a credential that does not expire.
    pub expires: u64,
}

impl Entry {
    fn parse(line: &str) -> Option<Entry> {
        let mut f = line.split('\t');
        let hash = f.next()?.trim().to_string();
        let name = f.next()?.trim().to_string();
        let expires = f.next().unwrap_or("0").trim().parse().unwrap_or(0);
        // A line missing either half is corrupt, not a credential that matches
        // everything — refuse it rather than letting it into the set.
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) || name.is_empty() {
            return None;
        }
        Some(Entry {
            hash: hash.to_ascii_lowercase(),
            name,
            expires,
        })
    }
}

/// Reads the file, skipping blanks, comments and corrupt records.
pub fn read(path: &Path) -> Vec<Entry> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(Entry::parse)
        .collect()
}

/// Who this credential belongs to, or `None` if unknown or expired.
/// Uses constant-time comparison to prevent side-channel timing attacks.
pub fn identify(entries: &[Entry], token: &str, now: u64) -> Option<String> {
    if token.is_empty() || token.len() > 1024 {
        return None;
    }
    let hash = sha256_hex(token.as_bytes());
    entries
        .iter()
        .find(|e| {
            crate::security::constant_time_eq_str(&e.hash, &hash)
                && (e.expires == 0 || e.expires > now)
        })
        .map(|e| e.name.clone())
}

/// The token file, re-read when it changes.
pub struct Tokens {
    path: PathBuf,
    cache: Mutex<(Option<SystemTime>, Vec<Entry>)>,
}

impl Tokens {
    pub fn new(path: PathBuf) -> Tokens {
        Tokens {
            path,
            cache: Mutex::new((None, Vec::new())),
        }
    }

    pub fn configured(&self) -> bool {
        !self.current().is_empty()
    }

    pub fn current(&self) -> Vec<Entry> {
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != mtime {
            *cache = (mtime, read(&self.path));
        }
        cache.1.clone()
    }

    pub fn identify(&self, token: Option<&str>, now: u64) -> Option<String> {
        identify(&self.current(), token?, now)
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// An OIDC resource-server validator backed by a locally mounted JWKS file.
/// The deployment refreshes that file from its IdP; re-reading it on mtime
/// makes key rotation take effect without restarting the control plane.
pub struct Oidc {
    issuer: String,
    audience: String,
    subject_claim: String,
    groups_claim: String,
    jwks: PathBuf,
    cache: Mutex<(Option<SystemTime>, Vec<Jwk>)>,
}

#[derive(Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

impl Oidc {
    pub fn new(
        issuer: String,
        audience: String,
        subject_claim: String,
        groups_claim: String,
        jwks: PathBuf,
    ) -> Oidc {
        Oidc {
            issuer,
            audience,
            subject_claim,
            groups_claim,
            jwks,
            cache: Mutex::new((None, Vec::new())),
        }
    }

    fn keys(&self) -> Vec<Jwk> {
        let mtime = std::fs::metadata(&self.jwks)
            .and_then(|m| m.modified())
            .ok();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != mtime {
            let keys = std::fs::read(&self.jwks)
                .ok()
                .and_then(|text| serde_json::from_slice::<Jwks>(&text).ok())
                .map(|set| set.keys)
                .unwrap_or_default();
            *cache = (mtime, keys);
        }
        cache.1.clone()
    }

    /// Validates the token and returns only explicitly configured group claims.
    /// A missing or malformed groups claim is an empty set, never an error that
    /// falls back to a permissive local role.
    pub fn identify_with_groups(&self, token: Option<&str>) -> Option<Identity> {
        let token = token?;
        if token.is_empty() || token.len() > 16 * 1024 {
            return None;
        }
        let header = decode_header(token).ok()?;
        if header.alg != Algorithm::RS256 {
            return None;
        }
        let kid = header.kid?;
        let key = self
            .keys()
            .into_iter()
            .find(|key| key.kty == "RSA" && key.kid.as_deref() == Some(kid.as_str()))?;
        let decoding =
            DecodingKey::from_rsa_components(key.n.as_deref()?, key.e.as_deref()?).ok()?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.validate_exp = true;
        let claims = decode::<Value>(token, &decoding, &validation).ok()?.claims;
        let subject = claims
            .get(&self.subject_claim)?
            .as_str()
            .filter(|subject| crate::security::is_valid_identifier(subject))
            .map(str::to_string)?;
        let groups = claims
            .get(&self.groups_claim)
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .filter(|group| crate::security::is_valid_identifier(group))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Some(Identity { subject, groups })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub groups: Vec<String>,
}

/// Validation report for user tokens.
#[derive(Debug, Default)]
pub struct TokensReport {
    pub valid_count: usize,
    pub expired_count: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl TokensReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validates a tokens file thoroughly.
pub fn validate_file(path: &Path, now: u64) -> std::io::Result<TokensReport> {
    let text = std::fs::read_to_string(path)?;
    Ok(validate_text(&text, now))
}

pub fn validate_text(text: &str, now: u64) -> TokensReport {
    let mut report = TokensReport::default();
    let mut seen_hashes = HashSet::new();

    for (idx, line) in text.lines().enumerate() {
        let line_num = idx + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split('\t');
        let hash = parts.next().map(str::trim).unwrap_or_default();
        let name = parts.next().map(str::trim).unwrap_or_default();
        let expires_str = parts.next().map(str::trim).unwrap_or("0");

        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            report.errors.push(format!(
                "line {line_num}: invalid SHA-256 hash '{hash}' (must be exactly 64 hex characters)"
            ));
            continue;
        }
        if name.is_empty() {
            report
                .errors
                .push(format!("line {line_num}: missing user name"));
            continue;
        }

        let expires = match expires_str.parse::<u64>() {
            Ok(exp) => exp,
            Err(_) => {
                report.errors.push(format!(
                    "line {line_num}: invalid expiration timestamp '{expires_str}'"
                ));
                continue;
            }
        };

        if !seen_hashes.insert(hash.to_ascii_lowercase()) {
            report.warnings.push(format!(
                "line {line_num}: duplicate token hash for user '{name}'"
            ));
        }

        if expires > 0 && expires <= now {
            report.expired_count += 1;
            report.warnings.push(format!(
                "line {line_num}: token for user '{name}' expired at Unix timestamp {expires}"
            ));
        } else {
            report.valid_count += 1;
        }
    }

    report
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256, per FIPS 180-4. Copied from the core — see the module comment.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut data = msg.to_vec();
    let bits = (msg.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bits.to_be_bytes());

    for chunk in data.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }

    let mut out = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Computes SHA-256 and returns a lowercase hex string.
pub fn sha256_hex(msg: &[u8]) -> String {
    hex(&sha256(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_published_vectors() {
        // FIPS 180-4. Everything else here trusts this: a hash that is merely
        // plausible makes every credential comparison silently wrong.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn an_expired_credential_is_refused_and_a_corrupt_line_grants_nothing() {
        let live = sha256_hex(b"good");
        let entries = read_str(&format!("{live}\tanna\t0\n{live}\tbruno\t100\ngarbage\n"));
        assert_eq!(entries.len(), 2, "the corrupt line is skipped");
        assert_eq!(identify(&entries, "good", 50).as_deref(), Some("anna"));
        // bruno's expired at 100; anna's never expires, so she still answers.
        assert_eq!(identify(&entries, "good", 200).as_deref(), Some("anna"));
        assert_eq!(identify(&entries, "wrong", 50), None);
    }

    #[test]
    fn validate_detects_malformed_hashes_and_expiry() {
        let valid_hash = sha256_hex(b"valid");
        let text = format!("{valid_hash}\tanna\t0\nshort_hash\tbad\t0\n{valid_hash}\told\t100\n");
        let report = validate_text(&text, 200);
        assert!(!report.is_valid());
        assert_eq!(report.valid_count, 1);
        assert_eq!(report.expired_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("invalid SHA-256 hash"))
        );
    }

    fn read_str(text: &str) -> Vec<Entry> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(Entry::parse)
            .collect()
    }
}
