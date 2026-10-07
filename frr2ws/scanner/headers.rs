use reqwest::Client;
use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

struct HeaderPolicy {
    name:        &'static str,
    severity:    Severity,
    description: &'static str,
    remediation: &'static str,
    value_check: Option<(&'static str, &'static str, Severity)>,
}

static POLICIES: &[HeaderPolicy] = &[
    HeaderPolicy {
        name: "Strict-Transport-Security",
        severity: Severity::High,
        description: "Missing HSTS header. Browsers will not enforce HTTPS connections.",
        remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        value_check: Some(("max-age=0", "HSTS max-age is 0 — effectively disabling HSTS", Severity::High)),
    },
    HeaderPolicy {
        name: "Content-Security-Policy",
        severity: Severity::High,
        description: "Missing CSP header. No restrictions on script/resource loading.",
        remediation: "Define a restrictive Content-Security-Policy appropriate for your application.",
        value_check: Some(("unsafe-inline", "CSP allows unsafe-inline scripts, weakening XSS protection", Severity::Medium)),
    },
    HeaderPolicy {
        name: "X-Frame-Options",
        severity: Severity::Medium,
        description: "Missing X-Frame-Options. Page may be embeddable in iframes (clickjacking).",
        remediation: "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)",
        value_check: None,
    },
    HeaderPolicy {
        name: "X-Content-Type-Options",
        severity: Severity::Low,
        description: "Missing X-Content-Type-Options. Browser may MIME-sniff responses.",
        remediation: "Add: X-Content-Type-Options: nosniff",
        value_check: None,
    },
    HeaderPolicy {
        name: "Referrer-Policy",
        severity: Severity::Low,
        description: "Missing Referrer-Policy. Full URL may leak to third parties via Referer header.",
        remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
        value_check: None,
    },
    HeaderPolicy {
        name: "Permissions-Policy",
        severity: Severity::Low,
        description: "Missing Permissions-Policy (formerly Feature-Policy).",
        remediation: "Add Permissions-Policy to restrict access to browser features (camera, mic, geolocation…).",
        value_check: None,
    },
    HeaderPolicy {
        name: "Cross-Origin-Opener-Policy",
        severity: Severity::Low,
        description: "Missing COOP header. Page shares a browsing context group with cross-origin openers.",
        remediation: "Add: Cross-Origin-Opener-Policy: same-origin",
        value_check: None,
    },
    HeaderPolicy {
        name: "Cross-Origin-Resource-Policy",
        severity: Severity::Low,
        description: "Missing CORP header.",
        remediation: "Add: Cross-Origin-Resource-Policy: same-origin",
        value_check: None,
    },
];

static DISCOURAGED: &[(&str, &str, Severity)] = &[
    ("Server",        "Server header discloses software/version", Severity::Low),
    ("X-Powered-By",  "X-Powered-By discloses backend technology",  Severity::Low),
    ("X-AspNet-Version", "X-AspNet-Version discloses framework version", Severity::Low),
    ("X-AspNetMvc-Version", "X-AspNetMvc-Version discloses framework version", Severity::Low),
];

pub async fn scan(client: &Client, url: &str, follow_redirects: bool) -> Result<ScanResult> {
    let mut result = ScanResult::new("headers", url);
    let req = if follow_redirects {
        client.get(url)
    } else {
        client.get(url)
    };

    let resp = req.send().await?;
    let headers = resp.headers().clone();
    let status  = resp.status();
    result = result.with_metadata(serde_json::json!({
        "status_code": status.as_u16(),
        "final_url":   resp.url().as_str(),
    }));

    for policy in POLICIES {
        match headers.get(policy.name) {
            None => {
                result.push(
                    Finding::new(policy.severity, format!("Missing {}", policy.name), policy.description)
                        .with_remediation(policy.remediation),
                );
            }
            Some(val) => {
                if let Some((bad_value, bad_desc, bad_sev)) = policy.value_check {
                    let v = val.to_str().unwrap_or("").to_lowercase();
                    if v.contains(&bad_value.to_lowercase()) {
                        result.push(
                            Finding::new(bad_sev, format!("Weak {} value", policy.name), bad_desc)
                                .with_evidence(format!("{}: {}", policy.name, val.to_str().unwrap_or("")))
                                .with_remediation(policy.remediation),
                        );
                    }
                }
            }
        }
    }

    for (name, desc, sev) in DISCOURAGED {
        if let Some(val) = headers.get(*name) {
            result.push(
                Finding::new(*sev, format!("Information disclosure via {name}"), *desc)
                    .with_evidence(format!("{name}: {}", val.to_str().unwrap_or("")))
                    .with_remediation(&format!("Remove or obscure the '{name}' header")),
            );
        }
    }

    match headers.get("Cache-Control") {
        None => {
            result.push(
                Finding::new(
                    Severity::Info,
                    "No Cache-Control header",
                    "Responses may be cached by proxies or browsers.",
                )
                .with_remediation("Add Cache-Control: no-store for authenticated / sensitive pages."),
            );
        }
        Some(val) => {
            let v = val.to_str().unwrap_or("").to_lowercase();
            if !v.contains("no-store") && !v.contains("no-cache") && !v.contains("private") {
                result.push(
                    Finding::new(
                        Severity::Info,
                        "Permissive Cache-Control",
                        "Cache-Control does not include no-store, no-cache, or private.",
                    )
                    .with_evidence(format!("Cache-Control: {}", val.to_str().unwrap_or("")))
                    .with_remediation("Use Cache-Control: no-store, max-age=0 for sensitive pages."),
                );
            }
        }
    }

    Ok(result)
}
