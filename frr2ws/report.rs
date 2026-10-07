use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info     => "INFO    ".cyan().bold(),
            Severity::Low      => "LOW     ".blue().bold(),
            Severity::Medium   => "MEDIUM  ".yellow().bold(),
            Severity::High     => "HIGH    ".red().bold(),
            Severity::Critical => "CRITICAL".red().on_black().bold(),
        };
        write!(f, "{s}")
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity:    Severity,
    pub title:       String,
    pub description: String,
    pub evidence:    Option<String>,
    pub remediation: Option<String>,
}

impl Finding {
    pub fn new(
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            title: title.into(),
            description: description.into(),
            evidence: None,
            remediation: None,
        }
    }

    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence = Some(ev.into());
        self
    }

    pub fn with_remediation(mut self, rem: impl Into<String>) -> Self {
        self.remediation = Some(rem.into());
        self
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner:  String,
    pub target:   String,
    pub findings: Vec<Finding>,
    pub metadata: serde_json::Value,
}

impl ScanResult {
    pub fn new(scanner: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            scanner:  scanner.into(),
            target:   target.into(),
            findings: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }

    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn with_metadata(mut self, v: serde_json::Value) -> Self {
        self.metadata = v;
        self
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub generated_at: DateTime<Utc>,
    pub target:       String,
    pub scans:        Vec<ScanResult>,
}

impl Report {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            generated_at: Utc::now(),
            target:       target.into(),
            scans:        Vec::new(),
        }
    }

    pub fn add(&mut self, result: ScanResult) {
        self.scans.push(result);
    }


    pub fn print_pretty(&self) {
        let border = "═".repeat(70);
        println!("\n{}", border.bright_white());
        println!(
            "  {}  {}",
            "PENTEST REPORT".bold().bright_white(),
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("  Target : {}", self.target.bright_cyan());
        println!("{}", border.bright_white());
        for scan in &self.scans {
            println!(
                "\n┌─ {} {} {}",
                "▶".bright_yellow(),
                scan.scanner.to_uppercase().bold(),
                format!("({})", scan.target).dimmed()
            );
            if scan.findings.is_empty() {
                println!("│  {} No findings", "✓".bright_green());
            } else {
                for f in &scan.findings {
                    println!("│");
                    println!("│  [{}] {}", f.severity, f.title.bold());
                    println!("│   {}", f.description.dimmed());
                    if let Some(ev) = &f.evidence {
                        println!("│   {} {}", "Evidence:".yellow(), ev);
                    }
                    if let Some(rem) = &f.remediation {
                        println!("│   {} {}", "Fix:".green(), rem);
                    }
                }
            }
            println!("└{}", "─".repeat(69));
        }

        println!("\n{}", "SUMMARY".bold().bright_white());
        let mut crit = 0usize;
        let mut high = 0usize;
        let mut med  = 0usize;
        let mut low  = 0usize;
        let mut info = 0usize;
        for scan in &self.scans {
            for f in &scan.findings {
                match f.severity {
                    Severity::Critical => crit += 1,
                    Severity::High     => high += 1,
                    Severity::Medium   => med  += 1,
                    Severity::Low      => low  += 1,
                    Severity::Info     => info += 1,
                }
            }
        }

        println!(
            "  {} Critical   {} High   {} Medium   {} Low   {} Info",
            crit.to_string().red().bold(),
            high.to_string().red(),
            med.to_string().yellow(),
            low.to_string().blue(),
            info.to_string().cyan(),
        );
        println!();
    }


    pub fn print_json(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }


    pub fn write_json(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).unwrap();
        std::fs::write(path, json)
    }
}
