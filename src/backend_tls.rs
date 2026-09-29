use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

pub struct BackendTls(pub Arc<ClientConfig>);
pub struct ServerTls(pub Arc<ServerConfig>);

fn certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let text = std::fs::read_to_string(path)?;
    let certs: Vec<_> = pem::parse_many(text)
        .map_err(std::io::Error::other)?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| CertificateDer::from(block.into_contents()))
        .collect();
    if certs.is_empty() {
        return Err(std::io::Error::other("no certificate in PEM"));
    }
    Ok(certs)
}

fn private_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let key_text = std::fs::read_to_string(path)?;
    pem::parse_many(key_text)
        .map_err(std::io::Error::other)?
        .into_iter()
        .find(|block| block.tag() == "PRIVATE KEY")
        .map(|block| PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(block.into_contents())))
        .ok_or_else(|| std::io::Error::other("mTLS key must be unencrypted PKCS#8 PEM"))
}

fn roots(ca: &str) -> std::io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certs(ca)? {
        roots.add(certificate).map_err(std::io::Error::other)?;
    }
    Ok(roots)
}

pub fn load(ca: &str, cert: &str, key: &str) -> std::io::Result<BackendTls> {
    let config = ClientConfig::builder()
        .with_root_certificates(roots(ca)?)
        .with_client_auth_cert(certs(cert)?, private_key(key)?)
        .map_err(std::io::Error::other)?;
    Ok(BackendTls(Arc::new(config)))
}

/// Loads a TLS server that requires every client to present a certificate from
/// the supplied private CA. This is deliberately separate from ordinary HTTP:
/// audit ingest must never silently downgrade a cross-boundary transport.
pub fn load_server(ca: &str, cert: &str, key: &str) -> std::io::Result<ServerTls> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots(ca)?))
        .build()
        .map_err(std::io::Error::other)?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(cert)?, private_key(key)?)
        .map_err(std::io::Error::other)?;
    Ok(ServerTls(Arc::new(config)))
}

pub fn forward(config: &BackendTls, addr: &str, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let host = addr.rsplit_once(':').map(|(host, _)| host).unwrap_or(addr);
    let server_name = ServerName::try_from(host.to_owned()).map_err(std::io::Error::other)?;
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let conn =
        ClientConnection::new(config.0.clone(), server_name).map_err(std::io::Error::other)?;
    let mut stream = StreamOwned::new(conn, tcp);
    stream.write_all(request)?;
    stream.flush()?;
    let mut reply = Vec::new();
    stream.take(32 * 1024 * 1024).read_to_end(&mut reply)?;
    Ok(reply)
}

pub fn accept(
    config: &ServerTls,
    tcp: TcpStream,
) -> std::io::Result<StreamOwned<ServerConnection, TcpStream>> {
    let conn = ServerConnection::new(config.0.clone()).map_err(std::io::Error::other)?;
    Ok(StreamOwned::new(conn, tcp))
}

/// Sends one bounded HTTP request through a mutually-authenticated TLS channel.
/// The endpoint grammar is intentionally narrow: HTTPS, a DNS name (or IP),
/// optional explicit port, and an absolute path. Audit configuration is
/// operator-owned, so rejecting clever URL forms is a security feature.
pub fn post(
    config: &BackendTls,
    url: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<()> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mTLS audit endpoint must use https://",
        )
    })?;
    let (authority, suffix) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains(['@', '?', '#', ' ']) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid mTLS audit authority",
        ));
    }
    let (_host, addr) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => {
            (host, authority.to_string())
        }
        Some(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid mTLS audit port",
            ));
        }
        None => (authority, format!("{authority}:443")),
    };
    let path = format!("/{suffix}");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid mTLS audit header",
            ));
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    let reply = forward(config, &addr, &bytes)?;
    let ok = reply.starts_with(b"HTTP/1.1 2") || reply.starts_with(b"HTTP/1.0 2");
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "mTLS audit ingest returned {}",
            String::from_utf8_lossy(&reply[..reply.len().min(80)])
        )))
    }
}
