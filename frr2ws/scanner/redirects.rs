use reqwest::{Client, redirect};
use url::Url;

use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

static PAYLOADS: &[(&str, &str)] = &[
    ("https://evil.com",                    "absolute HTTPS URL"),
    ("http://evil.com",                     "absolute HTTP URL"),
    ("//evil.com",                          "protocol-relative URL"),
    ("////evil.com",                        "quadruple-slash"),
    ("https:evil.com",                      "colon without slashes"),
    ("/\\evil.com",                         "backslash bypass"),
    ("/%2F%2Fevil.com",                     "URL-encoded //"),
    ("https://evil.com%2F@target.com",      "@ authority confusion"),
    ("\x0d\x0ahttps://evil.com",            "CRLF-injected redirect"),
    ("javascript:alert(document.origin)",   "javascript: URI"),
];

pub async fn scan(client: &Client, url: &str, param: &str) -> Result<ScanResult> {
    let mut result = ScanResult::new("redirects", url);

    let no_redirect = reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| client.clone());

    let base: Url = url.parse()?;

    for (payload, description) in PAYLOADS {
        let mut test_url = base.clone();
        test_url.query_pairs_mut().append_pair(param, payload);

        let resp = match no_redirect.get(test_url.as_str()).send().await {
            Ok(r)  => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();

        if !(300..=399).contains(&status) {
            continue;
        }

        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if location.is_empty() {
            continue;
        }

        let redirects_off_site = is_off_site(&location, &base);
        let has_javascript = location.trim_start().to_lowercase().starts_with("javascript:");

        if has_javascript {
            result.push(
                Finding::new(
                    Severity::Critical,
                    "Open redirect to javascript: URI",
                    &format!(
                        "Parameter '{param}' causes a redirect to a javascript: URI — \
                         directly executable by the browser."
                    ),
                )
                .with_evidence(format!(
                    "Payload: {payload} ({description})\nLocation: {location}\nHTTP: {status}"
                ))
                .with_remediation(
                    "Block javascript: URIs in redirect parameters. \
                     Validate all redirect destinations against an allowlist.",
                ),
            );
        } else if redirects_off_site {
            result.push(
                Finding::new(
                    Severity::High,
                    "Open redirect to external host",
                    &format!(
                        "Parameter '{param}' redirects to '{location}' (external). \
                         Attackers can use this to lend legitimacy to phishing URLs."
                    ),
                )
                .with_evidence(format!(
                    "Payload: {payload} ({description})\nLocation: {location}\nHTTP: {status}"
                ))
                .with_remediation(
                    "Use a server-side allowlist of trusted redirect destinations. \
                     Never use raw user input as a redirect URL.",
                ),
            );
        }
    }

    Ok(result)
}

fn is_off_site(location: &str, base: &Url) -> bool {
    if let Ok(loc_url) = Url::parse(location) {
        return loc_url.host_str() != base.host_str();
    }

    if location.starts_with("//") || location.starts_with("/\\") {
        return true;
    }

    if location.contains('\n') || location.contains('\r') {
        return true;
    }

    false
}
