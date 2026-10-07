mod cli;
mod error;
mod report;
mod scanner;

use clap::Parser;
use colored::Colorize;
use reqwest::{Client, header};

use cli::{Cli, Commands, OutputFormat};
use report::Report;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut default_headers = header::HeaderMap::new();
    default_headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_static("webpentest/0.1 (security-scanner)"),
    );

    let client = Client::builder()
        .default_headers(default_headers)
        .danger_accept_invalid_certs(true)   
        .cookie_store(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let (target, scan_results) = match &cli.command {

        Commands::Headers(args) => {
            let r = scanner::headers::scan(&client, &args.url, args.follow_redirects).await?;
            (args.url.clone(), vec![r])
        }

        Commands::Tls(args) => {
            let r = scanner::tls::scan(&args.host, args.port).await?;
            (format!("{}:{}", args.host, args.port), vec![r])
        }

        Commands::Sqli(args) => {
            let r = scanner::sqli::scan(&client, &args.url, &args.param, &args.extra).await?;
            (args.url.clone(), vec![r])
        }

        Commands::Xss(args) => {
            let r = scanner::xss::scan(&client, &args.url, &args.param).await?;
            (args.url.clone(), vec![r])
        }

        Commands::Cors(args) => {
            let r = scanner::cors::scan(&client, &args.url).await?;
            (args.url.clone(), vec![r])
        }

        Commands::Ports(args) => {
            let r = scanner::ports::scan(
                &args.host,
                args.start,
                args.end,
                args.timeout_ms,
                args.concurrency,
            ).await?;
            (args.host.clone(), vec![r])
        }

        Commands::Dirs(args) => {
            let r = scanner::dirs::scan(
                &client,
                &args.url,
                args.wordlist.as_deref(),
                args.concurrency,
                &args.status_codes,
            ).await?;
            (args.url.clone(), vec![r])
        }

        Commands::Cookies(args) => {
            let r = scanner::cookies::scan(&client, &args.url).await?;
            (args.url.clone(), vec![r])
        }

        Commands::Redirects(args) => {
            let r = scanner::redirects::scan(&client, &args.url, &args.param).await?;
            (args.url.clone(), vec![r])
        }

        Commands::Full(args) => {
            let url   = &args.url;
            let host  = extract_host(url);

            eprintln!("{} Running full assessment against {}", "►".bright_yellow(), url.bright_cyan());

            let mut results = Vec::new();

            eprint!("  {} Headers…", "·".dimmed());
            match scanner::headers::scan(&client, url, true).await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} TLS…", "·".dimmed());
            match scanner::tls::scan(&host, 443).await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} CORS…", "·".dimmed());
            match scanner::cors::scan(&client, url).await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} Cookies…", "·".dimmed());
            match scanner::cookies::scan(&client, url).await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} Ports ({}-{})…", "·".dimmed(), args.port_start, args.port_end);
            match scanner::ports::scan(&host, args.port_start, args.port_end, 400, 200).await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} Directories…", "·".dimmed());
            match scanner::dirs::scan(&client, url, args.wordlist.as_deref(), 40, "200,301,302,403").await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} SQLi probe…", "·".dimmed());
            match scanner::sqli::scan(&client, url, "id", &[]).await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} XSS probe…", "·".dimmed());
            match scanner::xss::scan(&client, url, "q").await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprint!("  {} Open redirect probe…", "·".dimmed());
            match scanner::redirects::scan(&client, url, "url").await {
                Ok(r)  => { eprintln!(" done"); results.push(r); }
                Err(e) => eprintln!(" {}: {e}", "error".red()),
            }

            eprintln!();
            (url.clone(), results)
        }
    };

    let mut report = Report::new(&target);
    for r in scan_results {
        report.add(r);
    }

    match cli.output {
        OutputFormat::Pretty => report.print_pretty(),
        OutputFormat::Json   => report.print_json(),
    }

    if let Some(path) = &cli.report {
        report.write_json(path)?;
        eprintln!("{} Report written to {}", "✓".green(), path.display());
    }

    Ok(())
}

fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| url.to_string())
}
