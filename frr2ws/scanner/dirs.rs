use std::collections::HashSet;

use futures::stream::{self, StreamExt};
use reqwest::Client;
use url::Url;

use crate::{
    error::Result,
    report::{Finding, Severity, ScanResult},
};

static BUILTIN_WORDLIST: &[&str] = &[
    // admin
    "admin", "administrator", "admin/login", "admin/index", "admin.php",
    "admin.html", "wp-admin", "wp-login.php", "controlpanel", "cpanel",
    // config
    ".env", ".env.local", ".env.backup", ".git/config", ".git/HEAD",
    ".gitignore", ".htaccess", ".htpasswd", "config.php", "config.yml",
    "config.yaml", "settings.py", "settings.php", "database.yml",
    "secrets.yml", "credentials.json", "application.properties",
    "web.config", "composer.json", "package.json", "Makefile",
    // backups
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "dump.sql", "site.tar.gz", "www.zip", "old",
    // common paths
    "login", "signin", "signup", "register", "logout",
    "api", "api/v1", "api/v2", "api/swagger", "swagger", "swagger-ui",
    "swagger-ui.html", "swagger.json", "openapi.json", "graphql",
    "graphiql", "metrics", "health", "healthz", "status",
    "debug", "trace", "actuator", "actuator/env", "actuator/health",
    "actuator/metrics", "actuator/logfile",
    // static
    "uploads", "files", "media", "static", "assets", "images",
    "img", "js", "css", "fonts",
    // info
    "server-status", "server-info", "phpinfo.php", "info.php",
    "test.php", "test.html", "robots.txt", "sitemap.xml",
    // CMS
    "wp-content/debug.log", "wp-json", "xmlrpc.php",
    "joomla", "drupal", "magento",
    // docs
    "docs", "documentation", "readme", "README.md", "CHANGELOG.md",
    "LICENSE", "Dockerfile", "docker-compose.yml", "k8s", "helm",
    "prometheus", "grafana", "kibana", "jenkins",
    // tokens
    "oauth/token", "oauth2/token", "token", "auth",
    "id_rsa", "id_rsa.pub", "private.key", "server.key",
];

#[derive(Debug, Clone)]
pub struct DirFinding {
    pub path:        String,
    pub status:      u16,
    pub content_len: u64,
}

pub async fn scan(
    client: &Client,
    base_url: &str,
    wordlist_path: Option<&std::path::Path>,
    concurrency: usize,
    status_codes: &str,
) -> Result<ScanResult> {
    let mut result = ScanResult::new("dirs", base_url);

    let accepted: HashSet<u16> = status_codes
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let words: Vec<String> = if let Some(path) = wordlist_path {
        std::fs::read_to_string(path)?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        BUILTIN_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    let base: Url = base_url.parse()?;
    let word_count = words.len();

    let mut dir_findings: Vec<DirFinding> = stream::iter(words)
        .map(|word| {
            let client = client.clone();
            let mut url = base.clone();
            {
                let mut path = url.path().trim_end_matches('/').to_string();
                path.push('/');
                path.push_str(&word);
                url.set_path(&path);
            }
            async move {
                match client.head(url.as_str()).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let len    = resp
                            .headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        Some(DirFinding { path: url.to_string(), status, content_len: len })
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|r| async move { r })
        .filter(|f| {
            let ok = accepted.contains(&f.status);
            async move { ok }
        })
        .collect()
        .await;

    dir_findings.sort_by_key(|f| f.status);

    result = result.with_metadata(serde_json::json!({
        "words_tested": word_count,
        "hits": dir_findings.len(),
        "paths": dir_findings.iter().map(|f| serde_json::json!({
            "url":    f.path,
            "status": f.status,
            "bytes":  f.content_len,
        })).collect::<Vec<_>>(),
    }));

    for df in &dir_findings {
        let (sev, title) = classify_path(&df.path, df.status);
        result.push(
            Finding::new(
                sev,
                title,
                &format!("Path '{}' returned HTTP {}.", df.path, df.status),
            )
            .with_evidence(format!("HTTP {} | {} bytes | {}", df.status, df.content_len, df.path))
            .with_remediation(remediation_for(&df.path, df.status)),
        );
    }

    if dir_findings.is_empty() {
        result.push(Finding::new(
            Severity::Info,
            "No interesting paths found",
            &format!("Tested {word_count} paths; none returned an accepted status code."),
        ));
    }

    Ok(result)
}

fn classify_path(path: &str, status: u16) -> (Severity, String) {
    let p = path.to_lowercase();

    if p.contains(".git") || p.contains(".env") || p.contains("private.key")
        || p.contains("id_rsa") || p.contains("credentials") || p.contains("secrets")
        || p.contains("backup.sql") || p.contains("dump.sql")
    {
        return (Severity::Critical, format!("Sensitive file exposed (HTTP {status})"));
    }

    if p.contains("admin") || p.contains("phpinfo") || p.contains("actuator")
        || p.contains("debug") || p.contains("config.php") || p.contains("web.config")
        || p.contains(".htpasswd") || p.contains("xmlrpc")
    {
        return (Severity::High, format!("Admin/config endpoint accessible (HTTP {status})"));
    }

    if p.contains("backup") || p.contains("swagger") || p.contains("openapi")
        || p.contains("graphql") || p.contains(".log") || p.contains("robots.txt")
    {
        return (Severity::Medium, format!("Potentially sensitive path accessible (HTTP {status})"));
    }

    (Severity::Info, format!("Path discovered (HTTP {status})"))
}

fn remediation_for(path: &str, status: u16) -> String {
    let p = path.to_lowercase();
    if p.contains(".git") {
        return "Remove .git directory from the web root or block access via server config.".into();
    }
    if p.contains(".env") || p.contains("secrets") || p.contains("credentials") {
        return "Remove secrets from web root. Never store secrets in version-controlled/public files.".into();
    }
    if p.contains("admin") && status == 200 {
        return "Restrict admin panel to trusted IP ranges or require VPN.".into();
    }
    if p.contains("actuator") {
        return "Restrict Spring Boot Actuator endpoints; enable security and expose only /health externally.".into();
    }
    "Restrict access to this path using server configuration or firewall rules.".into()
}
