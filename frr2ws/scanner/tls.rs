use std::net::TcpStream;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use crate::{
    error::{Result, SuiteError},
    report::{Finding, Severity, ScanResult},
};

pub async fn scan(host: &str, port: u16) -> Result<ScanResult> {
    let target = format!("{host}:{port}");
    let mut result = ScanResult::new("tls", &target);

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let config = Arc::new(config);

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| SuiteError::Tls(format!("Invalid server name: {e}")))?;

    let host_owned = host.to_string();
    let result_data = tokio::task::spawn_blocking(move || -> std::result::Result<serde_json::Value, String> {
        let stream = TcpStream::connect(&format!("{host_owned}:{port}"))
            .map_err(|e| format!("TCP connect failed: {e}"))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;

        let mut conn = rustls::ClientConnection::new(config, server_name)
            .map_err(|e| format!("TLS setup: {e}"))?;

        let mut tls_stream = rustls::Stream::new(&mut conn, &mut { stream });

        use std::io::Read;
        let mut buf = [0u8; 1];
        let _ = tls_stream.read(&mut buf); 

        let conn = tls_stream.conn;

        let version = conn.protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "Unknown".to_string());

        let cipher = conn.negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "Unknown".to_string());

        let certs = conn.peer_certificates().unwrap_or_default();
        let cert_count = certs.len();

        let mut cert_info = Vec::new();
        for (i, cert_der) in certs.iter().enumerate() {
            cert_info.push(serde_json::json!({
                "index": i,
                "der_len_bytes": cert_der.as_ref().len(),
            }));
        }

        Ok(serde_json::json!({
            "protocol_version": version,
            "cipher_suite":     cipher,
            "cert_chain_depth": cert_count,
            "certificates":     cert_info,
        }))
    })
    .await
    .map_err(|e| SuiteError::Tls(e.to_string()))?;

    match result_data {
        Ok(data) => {
            let version = data["protocol_version"].as_str().unwrap_or("Unknown");
            let cipher  = data["cipher_suite"].as_str().unwrap_or("Unknown");

            result = result.with_metadata(data.clone());

            if version.contains("TLSv1_0") || version.contains("TLSv1_1") {
                result.push(
                    Finding::new(
                        Severity::Critical,
                        "Deprecated TLS version in use",
                        &format!("Server negotiated {version}, which is deprecated and insecure."),
                    )
                    .with_remediation("Disable TLS 1.0 and 1.1; require TLS 1.2 minimum, prefer TLS 1.3."),
                );
            } else if version.contains("TLSv1_2") {
                result.push(
                    Finding::new(
                        Severity::Info,
                        "TLS 1.2 in use",
                        "TLS 1.2 is acceptable but TLS 1.3 is preferred.",
                    )
                    .with_remediation("Enable TLS 1.3 for improved security and performance."),
                );
            }

            let weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5"];
            for weak in &weak_ciphers {
                if cipher.to_uppercase().contains(weak) {
                    result.push(
                        Finding::new(
                            Severity::High,
                            format!("Weak cipher suite: {weak}"),
                            &format!("Negotiated cipher suite '{cipher}' contains weak component '{weak}'."),
                        )
                        .with_remediation("Configure the server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305)."),
                    );
                }
            }

            if cipher.contains("CBC") {
                result.push(
                    Finding::new(
                        Severity::Medium,
                        "CBC mode cipher in use",
                        "CBC mode ciphers are susceptible to BEAST and Lucky13 attacks in TLS 1.2.",
                    )
                    .with_evidence(format!("Cipher: {cipher}"))
                    .with_remediation("Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305) over CBC."),
                );
            }

            let depth = data["cert_chain_depth"].as_u64().unwrap_or(0);
            if depth == 0 {
                result.push(
                    Finding::new(
                        Severity::High,
                        "No certificate received",
                        "The server did not present a certificate during the TLS handshake.",
                    ),
                );
            }
        }
        Err(e) => {
            if e.contains("CertificateExpired") || e.contains("expired") {
                result.push(
                    Finding::new(
                        Severity::Critical,
                        "TLS certificate is expired",
                        "The server's certificate has passed its notAfter date.",
                    )
                    .with_remediation("Renew the certificate immediately."),
                );
            } else if e.contains("UnknownIssuer") || e.contains("self signed") {
                result.push(
                    Finding::new(
                        Severity::High,
                        "TLS certificate not trusted",
                        "The certificate is self-signed or issued by an untrusted CA.",
                    )
                    .with_remediation("Obtain a certificate from a trusted CA (e.g. Let's Encrypt)."),
                );
            } else {
                result.push(
                    Finding::new(
                        Severity::High,
                        "TLS handshake failed",
                        &format!("Could not complete TLS handshake: {e}"),
                    ),
                );
            }
        }
    }

    Ok(result)
}
