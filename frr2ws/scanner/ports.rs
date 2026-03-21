use std::net::SocketAddr;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;

use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

/// well known port
fn well_known(port: u16) -> Option<(&'static str, Option<(&'static str, Severity)>)> {
    Some(match port {
        21   => ("FTP",          Some(("FTP transmits credentials in cleartext; anonymous login may be enabled.", Severity::High))),
        22   => ("SSH",          Some(("SSH exposed. Ensure strong keys and fail2ban are configured.",            Severity::Info))),
        23   => ("Telnet",       Some(("Telnet is unencrypted. Replace with SSH immediately.",                   Severity::Critical))),
        25   => ("SMTP",         Some(("SMTP port open. Check for open relay.",                                  Severity::High))),
        53   => ("DNS",          Some(("DNS open. Verify zone-transfer is disabled.",                            Severity::Medium))),
        80   => ("HTTP",         None),
        110  => ("POP3",         Some(("POP3 is typically cleartext.",                                          Severity::Medium))),
        111  => ("RPC",          Some(("RPC portmapper exposed; can be used to enumerate services.",             Severity::Medium))),
        135  => ("MSRPC",        Some(("MSRPC exposed; often targeted by Windows exploits.",                    Severity::High))),
        139  => ("NetBIOS",      Some(("NetBIOS/SMB exposed; common attack surface.",                           Severity::High))),
        143  => ("IMAP",         Some(("IMAP cleartext credentials risk.",                                       Severity::Medium))),
        389  => ("LDAP",         Some(("LDAP exposed; check for anonymous bind.",                               Severity::High))),
        443  => ("HTTPS",        None),
        445  => ("SMB",          Some(("SMB exposed; high-value target (EternalBlue, ransomware).",             Severity::Critical))),
        465  => ("SMTPS",        None),
        587  => ("SMTP-sub",     None),
        631  => ("IPP",          Some(("IPP (printing) exposed; CUPS has had critical CVEs.",                   Severity::Medium))),
        993  => ("IMAPS",        None),
        995  => ("POP3S",        None),
        1433 => ("MSSQL",        Some(("MSSQL database port publicly reachable.",                              Severity::Critical))),
        1521 => ("Oracle-DB",    Some(("Oracle DB port publicly reachable.",                                    Severity::Critical))),
        2375 => ("Docker-HTTP",  Some(("Docker daemon HTTP API exposed — full host compromise possible.",       Severity::Critical))),
        2376 => ("Docker-TLS",   Some(("Docker TLS API exposed — verify client cert requirements.",            Severity::High))),
        3306 => ("MySQL",        Some(("MySQL port publicly reachable.",                                        Severity::Critical))),
        3389 => ("RDP",          Some(("RDP exposed; frequent target for brute-force and BlueKeep.",           Severity::High))),
        5432 => ("PostgreSQL",   Some(("PostgreSQL port publicly reachable.",                                   Severity::Critical))),
        5900 => ("VNC",          Some(("VNC exposed; often weakly authenticated.",                             Severity::High))),
        6379 => ("Redis",        Some(("Redis port exposed; frequently unauthenticated by default.",           Severity::Critical))),
        8080 => ("HTTP-alt",     None),
        8443 => ("HTTPS-alt",    None),
        9200 => ("Elasticsearch",Some(("Elasticsearch REST API exposed; often unauthenticated.",               Severity::Critical))),
        27017=> ("MongoDB",      Some(("MongoDB exposed; historically unauthenticated by default.",            Severity::Critical))),
        _    => return None,
    })
}

pub async fn scan(
    host: &str,
    start: u16,
    end: u16,
    timeout_ms: u64,
    concurrency: usize,
) -> Result<ScanResult> {
    let target_str = format!("{host}:{start}-{end}");
    let mut result = ScanResult::new("ports", &target_str);
    let timeout    = Duration::from_millis(timeout_ms);

    let addr_str = format!("{host}:0");
    let ip = tokio::net::lookup_host(&addr_str)
        .await?
        .next()
        .map(|a| a.ip())
        .unwrap_or_else(|| "0.0.0.0".parse().unwrap());

    let mut open_ports: Vec<u16> = stream::iter(start..=end)
        .map(|port| {
            let addr = SocketAddr::new(ip, port);
            async move {
                match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => Some(port),
                    _         => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    open_ports.sort_unstable();

    result = result.with_metadata(serde_json::json!({
        "host":       host,
        "range":      format!("{start}-{end}"),
        "open_ports": open_ports,
    }));

    for &port in &open_ports {
        match well_known(port) {
            Some((service, Some((note, sev)))) => {
                result.push(
                    Finding::new(
                        sev,
                        format!("Port {port}/tcp open – {service}"),
                        note,
                    )
                    .with_evidence(format!("{host}:{port}"))
                    .with_remediation("Restrict access with firewall rules if this port should not be public."),
                );
            }
            Some((service, None)) => {
                result.push(
                    Finding::new(
                        Severity::Info,
                        format!("Port {port}/tcp open – {service}"),
                        &format!("{service} port is open."),
                    )
                    .with_evidence(format!("{host}:{port}")),
                );
            }
            None => {
                result.push(
                    Finding::new(
                        Severity::Info,
                        format!("Port {port}/tcp open – unknown service"),
                        "Unknown service on open port.",
                    )
                    .with_evidence(format!("{host}:{port}")),
                );
            }
        }
    }

    if open_ports.is_empty() {
        result.push(
            Finding::new(
                Severity::Info,
                "No open ports found",
                &format!("All ports {start}-{end} are closed or filtered."),
            ),
        );
    }

    Ok(result)
}
