use reqwest::Client;

use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

static PROBE_ORIGINS: &[(&str, &str)] = &[
    ("https://evil.com",                     "arbitrary external origin"),
    ("null",                                 "null origin (sandboxed frame)"),
    ("https://target.attacker.com",          "attacker subdomain"),
    ("http://localhost",                     "localhost HTTP"),
    ("https://localhost",                    "localhost HTTPS"),
    ("https://127.0.0.1",                    "loopback IP"),
];

pub async fn scan(client: &Client, url: &str) -> Result<ScanResult> {
    let mut result = ScanResult::new("cors", url);

    for (origin, description) in PROBE_ORIGINS {
        let resp = match client
            .options(url)
            .header("Origin", *origin)
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "Authorization")
            .send()
            .await
        {
            Ok(r)  => r,
            Err(_) => continue,
        };

        let headers = resp.headers();

        let acao = headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let acac = headers
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if acao.is_empty() {
            if *origin == "null" {
            }
            continue;
        }

        if acao == "*" && acac == "true" {
            result.push(
                Finding::new(
                    Severity::Critical,
                    "CORS wildcard with credentials allowed",
                    "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true \
                     is forbidden by the spec but some servers misconfigure this.",
                )
                .with_evidence(format!("Origin probed: {origin}\nACAO: {acao}\nACAC: {acac}"))
                .with_remediation(
                    "Never combine a wildcard ACAO with Allow-Credentials. \
                     Explicitly whitelist trusted origins.",
                ),
            );
        }

        if acao == *origin && *origin != "null" {
            let sev = if acac == "true" {
                Severity::Critical
            } else {
                Severity::High
            };

            result.push(
                Finding::new(
                    sev,
                    format!("CORS reflects arbitrary origin ({description})"),
                    &format!(
                        "Server echoes the attacker-controlled origin '{origin}' in \
                         Access-Control-Allow-Origin. \
                         {}",
                        if acac == "true" {
                            "Credentials are also allowed — cookies/tokens are exposed to cross-origin requests."
                        } else {
                            "Credentials are not allowed, but cross-origin reads are still possible."
                        }
                    ),
                )
                .with_evidence(format!("ACAO: {acao}  |  ACAC: {acac}"))
                .with_remediation(
                    "Maintain an explicit whitelist of trusted origins and only reflect those. \
                     Validate the Origin header server-side before echoing.",
                ),
            );
        }

        if acao == "null" {
            result.push(
                Finding::new(
                    Severity::High,
                    "CORS allows null origin",
                    "Access-Control-Allow-Origin: null permits requests from sandboxed iframes \
                     and local HTML files, which attackers can control.",
                )
                .with_evidence(format!("ACAO: null | ACAC: {acac}"))
                .with_remediation(
                    "Do not whitelist the 'null' origin. \
                     Use explicit, scheme+host+port origins instead.",
                ),
            );
        }

        let vary = headers
            .get("vary")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if !acao.is_empty() && !vary.contains("origin") {
            result.push(
                Finding::new(
                    Severity::Low,
                    "CORS response missing Vary: Origin",
                    "When CORS headers are dynamic, Vary: Origin must be set to prevent \
                     CDN/proxy caches from serving the wrong ACAO to different clients.",
                )
                .with_remediation("Add 'Vary: Origin' to all CORS responses."),
            );
            break;
        }
    }

    Ok(result)
}
