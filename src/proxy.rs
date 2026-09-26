//! The forwarding half: authenticate, decide, hand the request to one backend.
//!
//! **Enterprise Security Hardening (2026):**
//! - **Strict URL normalization:** Percent-decoding and alphanumeric identifier validation
//!   before routing decisions are made (immune to `%2e%2e` and traversal bypasses).
//! - **RFC 9112 Request Smuggling Defense:** Strictly enforces single `Content-Length`
//!   and prohibits concurrent `Transfer-Encoding`.
//! - **Bounded Line Parsing:** Prevents Slowloris / memory blowup on unterminated headers.
//! - **Hop-by-hop & Credential Stripping:** Drops incoming caller tokens and hop headers.

use crate::rights::{Rights, Tree};
use crate::security;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// One parsed HTTP request. Only what routing needs.
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Bounded limits for memory safety.
const MAX_LINE_BYTES: usize = 8 * 1024; // 8 KB per line limit against Slowloris
const MAX_HEADERS: usize = 100; // Cap header count
const MAX_BODY: usize = 1024 * 1024; // 1 MB
/// Reads a line from a buffered reader with strict size bounds during stream consumption,
/// preventing Slowloris attacks from allocating unbounded memory before checking size limits.
pub fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let mut total = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let chunk = &available[..=pos];
            if total + chunk.len() > max {
                return Err(std::io::Error::other("line exceeds maximum allowed size"));
            }
            let text = std::str::from_utf8(chunk)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            line.push_str(text);
            reader.consume(pos + 1);
            break;
        } else {
            let len = available.len();
            if total + len > max {
                return Err(std::io::Error::other("line exceeds maximum allowed size"));
            }
            let text = std::str::from_utf8(available)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            line.push_str(text);
            total += len;
            reader.consume(len);
        }
    }
    Ok(Some(line))
}

pub fn read_request<R: Read>(stream: &mut BufReader<R>) -> std::io::Result<Option<Request>> {
    let Some(start) = read_bounded_line(stream, MAX_LINE_BYTES)? else {
        return Ok(None);
    };

    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    // No route reads a query, and the audit log records the path: a sign-on
    // code arriving at the console must not be written there.
    let target = parts.next().unwrap_or_default();
    let path = target
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();

    if !["GET", "POST", "HEAD", "OPTIONS"].contains(&method.as_str()) {
        return Err(std::io::Error::other(
            "unsupported or malformed HTTP method",
        ));
    }

    let mut headers = Vec::new();
    loop {
        if headers.len() >= MAX_HEADERS {
            return Err(std::io::Error::other(
                "too many headers (exceeds limit of 100)",
            ));
        }
        let Some(line) = read_bounded_line(stream, MAX_LINE_BYTES)? else {
            break;
        };
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    // RFC 9112 Request Smuggling & Desync Checks
    if let Err(smuggle_err) = security::validate_http_smuggling(&headers) {
        return Err(std::io::Error::other(format!(
            "RFC 9112 violation: {smuggle_err}"
        )));
    }

    // RFC 9112 §7.2: Duplicate Host header rejection
    let host_count = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .count();
    if host_count > 1 {
        return Err(std::io::Error::other(
            "multiple host headers rejected (RFC 9112)",
        ));
    }

    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    if length > MAX_BODY {
        return Err(std::io::Error::other(format!(
            "request body of {length} bytes exceeds the {MAX_BODY}-byte limit"
        )));
    }

    let mut body = vec![0u8; length];
    if length > 0 {
        stream.read_exact(&mut body)?;
    }

    Ok(Some(Request {
        method,
        path,
        headers,
        body,
    }))
}

const MAX_BACKEND_REPLY: u64 = 32 * 1024 * 1024; // 32 MB max reply limit

/// Which tree a path names: `/mcp/<tree>` and nothing else.
///
/// Decodes percent-encoding and strictly verifies identifier safety to prevent
/// directory traversal, null-byte poisoning, and alias spoofing.
pub fn tree_of(path: &str) -> Option<String> {
    let decoded = security::url_decode(path)?;
    let rest = decoded.strip_prefix("/mcp/")?;
    let name = rest.split(['/', '?']).next().unwrap_or(rest);
    if !security::is_valid_identifier(name) {
        return None;
    }
    Some(name.to_string())
}

/// What this request should do.
#[derive(Debug, PartialEq)]
pub enum Route {
    /// Forward to this tree.
    To(Tree),
    /// No credential, or one that is not known.
    Unauthenticated,
    /// Authenticated, but this tree is not theirs — or does not exist.
    ///
    /// **The two are one answer on purpose.** Telling them apart turns the
    /// service into an oracle for repository names, which is what a competitor
    /// would most like to have. B.4's acceptance criterion names this
    /// explicitly: a tree someone may not reach must be indistinguishable from
    /// one that is not there.
    NotFound,
}

/// Decides a request. Authentication first, then the grant, then the tree.
pub fn route(rights: &Rights, user: Option<&str>, path: &str) -> Route {
    let Some(user) = user else {
        return Route::Unauthenticated;
    };
    let Some(name) = tree_of(path) else {
        return Route::NotFound;
    };
    if !rights.may(user, &name) {
        return Route::NotFound;
    }
    match rights.tree(&name) {
        Some(t) => Route::To(t.clone()),
        // Granted but not configured: a rights file naming a tree that no
        // longer exists. Still NotFound, for the same reason as above.
        None => Route::NotFound,
    }
}

/// Sends the request to one backend and returns its whole response.
///
/// The caller's credential is dropped and ours is set instead. Passing theirs
/// through would make the backend trust a token it did not issue — the
/// token-passthrough problem the MCP security guidance forbids by name.
pub fn forward(
    tree: &Tree,
    req: &Request,
    tls: Option<&crate::backend_tls::BackendTls>,
) -> std::io::Result<Vec<u8>> {
    let head = backend_head(tree, req);
    if let Some(tls) = tls {
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&req.body);
        return crate::backend_tls::forward(tls, &tree.addr, &bytes);
    }
    let mut out = TcpStream::connect(&tree.addr)?;
    out.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    out.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    out.write_all(head.as_bytes())?;
    out.write_all(&req.body)?;
    out.flush()?;

    let mut reply = Vec::new();
    (&mut out).take(MAX_BACKEND_REPLY).read_to_end(&mut reply)?;
    Ok(reply)
}

/// Extracts the HTTP status code from a raw backend response buffer.
pub fn extract_status(reply: &[u8]) -> u16 {
    std::str::from_utf8(&reply[..reply.len().min(64)])
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(200)
}

/// The request line and headers sent to a backend.
///
/// Separate from `forward` so it can be asserted without a live socket — the
/// property that matters here is what the backend is told, not that a
/// connection succeeded.
pub fn backend_head(tree: &Tree, req: &Request) -> String {
    let mut head = format!("{} /mcp HTTP/1.1\r\n", req.method);
    for (k, v) in &req.headers {
        // Hop-by-hop and rewritten headers are not copied. `Host` is set to the
        // backend, `Authorization` is ours, and `Content-Length` is recomputed
        // — forwarding a stale one desynchronises the connection.
        if matches!(
            k.to_ascii_lowercase().as_str(),
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "host"
                | "content-length"
                | "connection"
                | "transfer-encoding"
                | "upgrade"
                | "x-forwarded-for"
                | "x-forwarded-proto"
                | "x-forwarded-host"
                // Browser origins are validated at the public control-plane
                // edge. Passing one to the loopback core would make its DNS
                // rebinding defence reject an otherwise authorized request.
                | "origin"
        ) {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!("Host: {}\r\n", tree.addr));
    head.push_str(&format!("Authorization: Bearer {}\r\n", tree.token));
    head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    head.push_str("Connection: close\r\n\r\n");
    head
}
