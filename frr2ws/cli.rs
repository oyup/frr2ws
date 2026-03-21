use clap::{Parser, Subcommand, Args};

#[derive(Parser, Debug)]
#[command(
    name        = "webpentest",
    version     = "0.1.0",
    about       = "pentesting suite Rust",
    long_about  = None,
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    #[arg(long, default_value = "pretty", global = true)]
    pub output: OutputFormat,
    #[arg(long, short = 'o', global = true)]
    pub report: Option<std::path::PathBuf>,
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Headers(HeaderArgs),
    Tls(TlsArgs),
    Sqli(SqliArgs),
    Xss(XssArgs),
    Cors(CorsArgs),
    Ports(PortArgs),
    Dirs(DirArgs),
    Cookies(CookieArgs),
    Redirects(RedirectArgs),
    Full(FullArgs),
}

#[derive(Args, Debug)]
pub struct HeaderArgs {
    pub url: String,
    #[arg(long, default_value_t = true)]
    pub follow_redirects: bool,
}

#[derive(Args, Debug)]
pub struct TlsArgs {
    pub host: String,
    #[arg(long, default_value_t = 443)]
    pub port: u16,
}

#[derive(Args, Debug)]
pub struct SqliArgs {
    pub url: String,
    #[arg(long, default_value = "id")]
    pub param: String,
    #[arg(long)]
    pub extra: Vec<String>,
}

#[derive(Args, Debug)]
pub struct XssArgs {
    pub url: String,
    #[arg(long, default_value = "q")]
    pub param: String,
}

#[derive(Args, Debug)]
pub struct CorsArgs {
    pub url: String,
}

#[derive(Args, Debug)]
pub struct PortArgs {
    pub host: String,
    #[arg(long, default_value_t = 1)]
    pub start: u16,
    #[arg(long, default_value_t = 1024)]
    pub end: u16,
    #[arg(long, default_value_t = 400)]
    pub timeout_ms: u64,
    #[arg(long, default_value_t = 200)]
    pub concurrency: usize,
}

#[derive(Args, Debug)]
pub struct DirArgs {
    pub url: String,
    #[arg(long)]
    pub wordlist: Option<std::path::PathBuf>,
    #[arg(long, default_value_t = 40)]
    pub concurrency: usize,
    #[arg(long, default_value = "200,301,302,403")]
    pub status_codes: String,
}

#[derive(Args, Debug)]
pub struct CookieArgs {
    pub url: String,
}

#[derive(Args, Debug)]
pub struct RedirectArgs {
    pub url: String,
    #[arg(long, default_value = "url")]
    pub param: String,
}

#[derive(Args, Debug)]
pub struct FullArgs {
    pub url: String,
    #[arg(long)]
    pub wordlist: Option<std::path::PathBuf>,
    #[arg(long, default_value_t = 1)]
    pub port_start: u16,
    #[arg(long, default_value_t = 1024)]
    pub port_end: u16,
}
