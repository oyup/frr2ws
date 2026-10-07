use reqwest::Client;
use url::Url;

use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

static PAYLOADS: &[(&str, &str)] = &[
    ("<script>xsstest</script>",    "<script>xsstest</script>"),
    ("<img src=x onerror=xsstest>", "onerror=xsstest"),
    ("<svg onload=xsstest>",        "onload=xsstest"),
    ("\"><script>xsstest</script>", "<script>xsstest</script>"),
    ("\" autofocus onfocus=xsstest //", "onfocus=xsstest"),
    ("{{7*7}}",                     "49"),
    ("&lt;script&gt;xsstest&lt;/script&gt;", "xsstest"),
    ("<input id=x>",                "<input id=x>"),
    ("\"><style>*{xss:expression(xsstest)}</style>", "xss:expression"),
    ("%00<script>xsstest</script>", "<script>xsstest</script>"),
];

pub async fn scan(client: &Client, url: &str, param: &str) -> Result<ScanResult> {
    let mut result = ScanResult::new("xss", url);
    let base: Url = url.parse()?;
    for (payload, pattern) in PAYLOADS {
        let mut test_url = base.clone();
        test_url.query_pairs_mut().append_pair(param, payload);
        let resp = match client.get(test_url.as_str()).send().await {
            Ok(r)  => r,
            Err(_) => continue,
        };

        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let body = resp.text().await?;
        if ct.contains("json") || ct.contains("xml") {
            if body.contains(payload.trim_start_matches('"')) {
                result.push(
                    Finding::new(
                        Severity::Low,
                        "XSS payload reflected into non-HTML response",
                        &format!(
                            "Parameter '{param}' reflects payload into a {ct} response. \
                             Not directly exploitable as XSS but may indicate insufficient output encoding.",
                        ),
                    )
                    .with_evidence(format!("Payload: {payload}\nURL: {test_url}"))
                    .with_remediation("Ensure all output is properly encoded for the content type."),
                );
            }
            continue;
        }

        if body.contains(pattern) {
            let severity = if payload.contains("<script") || payload.contains("onerror") || payload.contains("onload") {
                Severity::Critical
            } else {
                Severity::High
            };

            result.push(
                Finding::new(
                    severity,
                    "Reflected XSS – payload echoed unencoded",
                    &format!(
                        "Parameter '{param}' reflects the payload unescaped into the HTML response body."
                    ),
                )
                .with_evidence(format!("Payload: {payload}\nPattern found: {pattern}\nURL: {test_url}"))
                .with_remediation(
                    "HTML-encode all user-supplied output. \
                     Use a templating engine with auto-escaping (e.g. Tera, Askama). \
                     Implement a strict Content-Security-Policy.",
                ),
            );
        }
    }

    if let Ok(head_resp) = client.head(url).send().await {
        let hdr = head_resp.headers().get("X-XSS-Protection");
        if let Some(val) = hdr {
            let v = val.to_str().unwrap_or("").trim().to_lowercase();
            if v == "0" {
                result.push(
                    Finding::new(
                        Severity::Info,
                        "X-XSS-Protection disabled",
                        "X-XSS-Protection: 0 explicitly disables the legacy browser XSS auditor.",
                    )
                    .with_remediation(
                        "Rely on CSP instead. The header is deprecated but setting 0 disables \
                         the auditor on older browsers.",
                    ),
                );
            }
        }
    }

    Ok(result)
}
