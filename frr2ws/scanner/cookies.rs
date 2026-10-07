use reqwest::Client;

use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

pub async fn scan(client: &Client, url: &str) -> Result<ScanResult> {
    let mut result = ScanResult::new("cookies", url);
    let resp = client.get(url).send().await?;
    let is_https = url.starts_with("https://");
    let set_cookie_headers: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    if set_cookie_headers.is_empty() {
        result.push(Finding::new(
            Severity::Info,
            "No cookies set",
            "The response does not set any cookies.",
        ));
        return Ok(result);
    }

    for raw in &set_cookie_headers {
        let name = raw.split('=').next().unwrap_or("unknown").trim().to_string();
        let lower = raw.to_lowercase();
        let has_secure    = lower.contains("; secure")    || lower.contains(";secure");
        let has_httponly  = lower.contains("; httponly")  || lower.contains(";httponly");
        let has_samesite  = lower.contains("; samesite")  || lower.contains(";samesite");
        let samesite_none = lower.contains("samesite=none");
        let samesite_lax  = lower.contains("samesite=lax");
        if is_https && !has_secure {
            result.push(
                Finding::new(
                    Severity::High,
                    format!("Cookie '{name}' missing Secure flag"),
                    "Without the Secure flag the cookie may be transmitted over HTTP, \
                     making it vulnerable to interception.",
                )
                .with_evidence(raw.clone())
                .with_remediation("Add the Secure attribute: Set-Cookie: name=value; Secure; ..."),
            );
        }

        if !has_httponly {
            let sev = if is_session_cookie(&name, &lower) {
                Severity::High
            } else {
                Severity::Medium
            };
            result.push(
                Finding::new(
                    sev,
                    format!("Cookie '{name}' missing HttpOnly flag"),
                    "Without HttpOnly, JavaScript can read this cookie, enabling theft via XSS.",
                )
                .with_evidence(raw.clone())
                .with_remediation("Add the HttpOnly attribute: Set-Cookie: name=value; HttpOnly; ..."),
            );
        }

        if !has_samesite {
            result.push(
                Finding::new(
                    Severity::Medium,
                    format!("Cookie '{name}' missing SameSite attribute"),
                    "Without SameSite, the cookie is sent on cross-origin requests, \
                     enabling CSRF attacks in older browsers.",
                )
                .with_evidence(raw.clone())
                .with_remediation("Add SameSite=Lax or SameSite=Strict to protect against CSRF."),
            );
        } else if samesite_none && !has_secure {
            result.push(
                Finding::new(
                    Severity::High,
                    format!("Cookie '{name}' has SameSite=None without Secure"),
                    "SameSite=None requires the Secure flag; browsers reject the cookie otherwise.",
                )
                .with_evidence(raw.clone())
                .with_remediation("Add Secure alongside SameSite=None."),
            );
        }

        if samesite_lax && is_session_cookie(&name, &lower) {
            result.push(
                Finding::new(
                    Severity::Info,
                    format!("Session cookie '{name}' uses SameSite=Lax"),
                    "SameSite=Lax still allows the cookie to be sent on top-level GET navigations. \
                     Consider SameSite=Strict for session tokens.",
                )
                .with_evidence(raw.clone()),
            );
        }

        let has_expiry = lower.contains("max-age=") || lower.contains("expires=");
        if !has_expiry && is_session_cookie(&name, &lower) {
            result.push(
                Finding::new(
                    Severity::Info,
                    format!("Session cookie '{name}' has no expiry"),
                    "A cookie without Max-Age/Expires is a session cookie (deleted on browser close). \
                     This is intentional for session tokens, but confirm it's expected.",
                )
                .with_evidence(raw.clone()),
            );
        }

        if let Some(domain_val) = extract_attr(&lower, "domain=") {
            if domain_val.starts_with('.') {
                result.push(
                    Finding::new(
                        Severity::Low,
                        format!("Cookie '{name}' scoped to parent domain '{domain_val}'"),
                        "A leading dot makes the cookie available to all subdomains, \
                         increasing the attack surface.",
                    )
                    .with_evidence(raw.clone())
                    .with_remediation(
                        "Scope the cookie to the specific hostname unless subdomain sharing is intentional.",
                    ),
                );
            }
        }
    }

    result = result.with_metadata(serde_json::json!({
        "cookie_count": set_cookie_headers.len(),
    }));

    Ok(result)
}

fn is_session_cookie(name: &str, raw_lower: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("session")
        || n.contains("sess")
        || n.contains("auth")
        || n.contains("token")
        || n.contains("jwt")
        || n.contains("sid")
        || n == "connect.sid"
        || n == "phpsessid"
        || n == "jsessionid"
        || raw_lower.contains("httponly") 
}

fn extract_attr<'a>(lower: &'a str, prefix: &str) -> Option<&'a str> {
    let idx = lower.find(prefix)?;
    let rest = &lower[idx + prefix.len()..];
    let end  = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim())
}
