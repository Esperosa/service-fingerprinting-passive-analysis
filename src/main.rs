use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use bakula_program::{
    ai, automation, broker, config, context, correlation, cpe, decision, diff, evaluation,
    external_sql, findings, intel, lanes,
    model::{AppConfig, MonitoringLane, NormalizedEvent, RunReport, Severity, TriageAction},
    nmap, passive, paths, pentest, platform, readiness, report, server, simulation,
    storage::Workspace,
    triage, validation, verification, vuln, webscan,
};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;

#[derive(Parser, Debug)]
#[command(
    name = "bakula",
    version,
    about = "Bakula - korelace aktivniho a pasivniho pohledu na sit."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(subcommand)]
    Simulace(SimulaceCommand),
    #[command(subcommand)]
    Beh(BehCommand),
    #[command(subcommand)]
    Autopilot(AutopilotCommand),
    #[command(subcommand)]
    Monitor(MonitorCommand),
    #[command(subcommand)]
    Overeni(OvereniCommand),
    #[command(subcommand)]
    Evaluace(EvaluaceCommand),
    #[command(subcommand)]
    Server(ServerCommand),
    #[command(subcommand)]
    Config(ConfigCommand),
    #[command(subcommand)]
    Ai(AiCommand),
    Readiness(ReadinessArgs),
    #[command(subcommand)]
    Platform(PlatformCommand),
    #[command(subcommand)]
    Broker(BrokerCommand),
    #[command(subcommand)]
    ExternalSql(ExternalSqlCommand),
    #[command(subcommand)]
    Demo(DemoCommand),
}

#[derive(Subcommand, Debug)]
enum SimulaceCommand {
    Generuj(SimulaceArgs),
}

#[derive(Args, Debug)]
struct SimulaceArgs {
    #[arg(long)]
    vystup: PathBuf,
    #[arg(long, default_value_t = 7)]
    seed: u64,
    #[arg(long, default_value_t = 0)]
    nahodnych: usize,
    #[arg(long, default_value = "standard")]
    profil: String,
    #[arg(long)]
    extra_hostu: Option<usize>,
    #[arg(long)]
    max_sluzeb_na_host: Option<usize>,
    #[arg(long)]
    telemetrie_na_host: Option<usize>,
    #[arg(long)]
    flow_repetitions: Option<usize>,
}

#[derive(Subcommand, Debug)]
enum BehCommand {
    Spust(BehArgs),
}

#[derive(Args, Debug, Clone)]
struct BehArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    nazev: String,
    #[arg(long, value_delimiter = ',')]
    scope: Vec<IpNet>,
    #[arg(long, value_delimiter = ',', default_value = "21,22,23,80,443,8080")]
    ports: Vec<u16>,
    #[arg(long, default_value = "bezny")]
    profile: String,
    #[arg(long, default_value = "demo")]
    provider: String,
    #[arg(long, default_value_t = false)]
    supplement_vulners: bool,
    #[arg(long, default_value_t = false)]
    freeze: bool,
    #[arg(long, default_value_t = false)]
    production: bool,
    #[arg(long)]
    nmap_xml: Option<PathBuf>,
    #[arg(long)]
    nmap_followup_xml: Option<PathBuf>,
    #[arg(long)]
    suricata_eve: Option<PathBuf>,
    #[arg(long)]
    zeek_dir: Option<PathBuf>,
    #[arg(long)]
    porovnat_s: Option<String>,
    #[arg(long)]
    spustit_nmap: bool,
    #[arg(long, default_value_t = false)]
    hloubkove_overeni: bool,
    #[arg(long, default_value_t = false)]
    web_fingerprint: bool,
    #[arg(long, default_value_t = false)]
    web_checks: bool,
    #[arg(long, default_value_t = false)]
    pentest: bool,
    #[arg(long, default_value_t = false)]
    aggressive_pentest: bool,
    #[arg(long)]
    httpx_bin: Option<PathBuf>,
    #[arg(long)]
    nuclei_bin: Option<PathBuf>,
    #[arg(long)]
    nuclei_templates: Option<PathBuf>,
    #[arg(long)]
    snmp_snapshot: Option<PathBuf>,
    #[arg(long)]
    librenms_snapshot: Option<PathBuf>,
    #[arg(long)]
    librenms_base_url: Option<String>,
    #[arg(long, default_value = "LIBRENMS_TOKEN")]
    librenms_token_env: String,
    #[arg(long)]
    meraki_snapshot: Option<PathBuf>,
    #[arg(long)]
    meraki_network_id: Option<String>,
    #[arg(long, default_value = "MERAKI_DASHBOARD_API_KEY")]
    meraki_api_key_env: String,
    #[arg(long, default_value_t = 86400)]
    meraki_timespan_seconds: u32,
    #[arg(long)]
    unifi_snapshot: Option<PathBuf>,
    #[arg(long)]
    unifi_devices_url: Option<String>,
    #[arg(long)]
    unifi_clients_url: Option<String>,
    #[arg(long)]
    unifi_links_url: Option<String>,
    #[arg(long, default_value = "UNIFI_API_KEY")]
    unifi_api_key_env: String,
    #[arg(long)]
    aruba_snapshot: Option<PathBuf>,
    #[arg(long)]
    aruba_base_url: Option<String>,
    #[arg(long, default_value = "ARUBA_CENTRAL_TOKEN")]
    aruba_token_env: String,
    #[arg(long)]
    aruba_site_id: Option<String>,
    #[arg(long)]
    omada_snapshot: Option<PathBuf>,
    #[arg(long)]
    omada_devices_url: Option<String>,
    #[arg(long)]
    omada_clients_url: Option<String>,
    #[arg(long)]
    omada_links_url: Option<String>,
    #[arg(long, default_value = "OMADA_ACCESS_TOKEN")]
    omada_access_token_env: String,
    #[arg(long)]
    ntopng_snapshot: Option<PathBuf>,
    #[arg(long)]
    flow_snapshot: Option<PathBuf>,
    #[arg(long)]
    greenbone_report: Option<PathBuf>,
    #[arg(long)]
    wazuh_report: Option<PathBuf>,
    #[arg(long)]
    napalm_snapshot: Option<PathBuf>,
    #[arg(long)]
    netmiko_snapshot: Option<PathBuf>,
    #[arg(long)]
    scrapli_snapshot: Option<PathBuf>,
    #[arg(long, default_value = "URLHAUS_AUTH_KEY")]
    urlhaus_auth_env: String,
    #[arg(long, default_value = "ABUSEIPDB_API_KEY")]
    abuseipdb_key_env: String,
    #[arg(long, default_value_t = false)]
    disable_circl: bool,
}

#[derive(Subcommand, Debug)]
enum AutopilotCommand {
    Spust(AutopilotArgs),
}

#[derive(Args, Debug, Clone)]
struct AutopilotArgs {
    #[command(flatten)]
    run: BehArgs,
    #[arg(long, default_value_t = 2)]
    cycles: usize,
    #[arg(long, default_value_t = 0)]
    interval_s: u64,
}

#[derive(Subcommand, Debug)]
enum MonitorCommand {
    Spust(MonitorArgs),
}

#[derive(Args, Debug, Clone)]
struct MonitorArgs {
    #[command(flatten)]
    run: BehArgs,
    #[arg(long, default_value_t = 1)]
    cycles: usize,
    #[arg(long, default_value_t = 60)]
    interval_s: u64,
    #[arg(long, default_value_t = false)]
    continuous: bool,
}

#[derive(Subcommand, Debug)]
enum OvereniCommand {
    Spust(OvereniArgs),
}

#[derive(Args, Debug)]
struct OvereniArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    scenare: PathBuf,
    #[arg(long, default_value = "demo")]
    provider: String,
    #[arg(long, default_value_t = false)]
    freeze: bool,
}

#[derive(Subcommand, Debug)]
enum EvaluaceCommand {
    Spust(EvaluaceArgs),
}

#[derive(Args, Debug)]
struct EvaluaceArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    scenare: Option<PathBuf>,
    #[arg(long, default_value_t = 17)]
    seed: u64,
    #[arg(long, default_value_t = 120)]
    nahodnych: usize,
    #[arg(long, default_value_t = 8)]
    workers: usize,
    #[arg(long, default_value = "demo")]
    provider: String,
    #[arg(long, default_value_t = false)]
    freeze: bool,
    #[arg(long, default_value = "standard")]
    profil: String,
    #[arg(long)]
    extra_hostu: Option<usize>,
    #[arg(long)]
    max_sluzeb_na_host: Option<usize>,
    #[arg(long)]
    telemetrie_na_host: Option<usize>,
    #[arg(long)]
    flow_repetitions: Option<usize>,
}

#[derive(Subcommand, Debug)]
enum ServerCommand {
    Spust(ServerArgs),
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    Init(ConfigArgs),
    Validate(ConfigArgs),
}

#[derive(Subcommand, Debug)]
enum AiCommand {
    Diagnostika,
    Setup(AiSetupArgs),
    Modelfile(AiModelfileArgs),
    Test(AiTestArgs),
}

#[derive(Args, Debug)]
struct AiSetupArgs {
    #[arg(long, default_value_t = false)]
    pull: bool,
    #[arg(long, default_value = "models/skoky/Modelfile")]
    modelfile: PathBuf,
}

#[derive(Args, Debug)]
struct AiModelfileArgs {
    #[arg(long, default_value = "models/skoky/Modelfile")]
    vystup: PathBuf,
}

#[derive(Args, Debug)]
struct AiTestArgs {
    #[arg(long, default_value = "Co mám řešit jako první a proč?")]
    prompt: String,
}

#[derive(Args, Debug)]
struct ReadinessArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long, default_value_t = false)]
    require_api_token: bool,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    #[arg(long, default_value = "bakula.toml")]
    path: PathBuf,
}

#[derive(Args, Debug)]
struct ServerArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    api_token_env: Option<String>,
    #[arg(long, default_value_t = false)]
    require_api_token: bool,
}

#[derive(Subcommand, Debug)]
enum DemoCommand {
    E2e(DemoArgs),
}

#[derive(Subcommand, Debug)]
enum BrokerCommand {
    PublishDue(BrokerPublishArgs),
    WorkerRun(BrokerWorkerArgs),
}

#[derive(Subcommand, Debug)]
enum ExternalSqlCommand {
    Init(ExternalSqlInitArgs),
    #[command(subcommand)]
    User(ExternalSqlUserCommand),
    #[command(subcommand)]
    Token(ExternalSqlTokenCommand),
    #[command(subcommand)]
    Ha(ExternalSqlHaCommand),
    #[command(subcommand)]
    Job(ExternalSqlJobCommand),
    Status(ExternalSqlDbArgs),
}

#[derive(Subcommand, Debug)]
enum PlatformCommand {
    Init(PlatformInitArgs),
    #[command(subcommand)]
    User(PlatformUserCommand),
    #[command(subcommand)]
    Token(PlatformTokenCommand),
    #[command(subcommand)]
    Job(PlatformJobCommand),
    #[command(subcommand)]
    Worker(PlatformWorkerCommand),
    #[command(subcommand)]
    Ha(PlatformHaCommand),
    Status(PlatformStatusArgs),
}

#[derive(Args, Debug)]
struct PlatformInitArgs {
    #[arg(long)]
    db: PathBuf,
}

#[derive(Subcommand, Debug)]
enum PlatformUserCommand {
    Add(PlatformUserAddArgs),
    List(PlatformDbArgs),
}

#[derive(Args, Debug)]
struct PlatformUserAddArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    username: String,
    #[arg(long)]
    role: String,
}

#[derive(Subcommand, Debug)]
enum PlatformTokenCommand {
    Issue(PlatformTokenIssueArgs),
}

#[derive(Args, Debug)]
struct PlatformTokenIssueArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    username: String,
    #[arg(long)]
    name: String,
}

#[derive(Subcommand, Debug)]
enum PlatformJobCommand {
    EnqueueScenario(PlatformJobScenarioArgs),
    List(PlatformDbArgs),
}

#[derive(Args, Debug)]
struct PlatformJobScenarioArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    scenario_dir: PathBuf,
    #[arg(long)]
    nazev: String,
    #[arg(long, value_delimiter = ',')]
    scope: Vec<IpNet>,
    #[arg(long, value_delimiter = ',', default_value = "21,22,23,80,443,8080")]
    ports: Vec<u16>,
    #[arg(long, default_value = "bezny")]
    profile: String,
    #[arg(long, default_value = "demo")]
    provider: String,
    #[arg(long)]
    schedule_interval_s: Option<i64>,
    #[arg(long)]
    broker_uri: Option<String>,
}

#[derive(Subcommand, Debug)]
enum PlatformWorkerCommand {
    Run(PlatformWorkerArgs),
}

#[derive(Subcommand, Debug)]
enum PlatformHaCommand {
    SetPolicy(PlatformHaPolicyArgs),
    RegisterNode(PlatformHaRegisterNodeArgs),
    MarkReady(PlatformHaMarkReadyArgs),
    Plan(PlatformDbArgs),
    Advance(PlatformDbArgs),
}

#[derive(Args, Debug)]
struct PlatformWorkerArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long, default_value_t = 30)]
    leader_ttl_s: i64,
    #[arg(long, default_value_t = 120)]
    job_lease_s: i64,
    #[arg(long, default_value_t = false)]
    once: bool,
    #[arg(long)]
    broker_uri: Option<String>,
}

#[derive(Args, Debug)]
struct PlatformStatusArgs {
    #[arg(long)]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct PlatformDbArgs {
    #[arg(long)]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct PlatformHaPolicyArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    quorum: i64,
    #[arg(long)]
    min_ready: i64,
    #[arg(long, default_value_t = 1)]
    batch_size: i64,
    #[arg(long)]
    target_version: Option<String>,
}

#[derive(Args, Debug)]
struct PlatformHaRegisterNodeArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    version: String,
    #[arg(long, default_value_t = true)]
    ready: bool,
}

#[derive(Args, Debug)]
struct PlatformHaMarkReadyArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    version: String,
}

#[derive(Args, Debug)]
struct BrokerPublishArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    broker_uri: String,
}

#[derive(Args, Debug)]
struct BrokerWorkerArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    broker_uri: String,
    #[arg(long)]
    node_id: String,
    #[arg(long, default_value_t = 120)]
    lease_s: i64,
}

#[derive(Args, Debug)]
struct ExternalSqlInitArgs {
    #[arg(long)]
    db_uri: String,
}

#[derive(Subcommand, Debug)]
enum ExternalSqlUserCommand {
    Add(ExternalSqlUserAddArgs),
    List(ExternalSqlDbArgs),
}

#[derive(Args, Debug)]
struct ExternalSqlUserAddArgs {
    #[arg(long)]
    db_uri: String,
    #[arg(long)]
    username: String,
    #[arg(long)]
    role: String,
}

#[derive(Subcommand, Debug)]
enum ExternalSqlTokenCommand {
    Issue(ExternalSqlTokenIssueArgs),
}

#[derive(Args, Debug)]
struct ExternalSqlTokenIssueArgs {
    #[arg(long)]
    db_uri: String,
    #[arg(long)]
    username: String,
    #[arg(long)]
    name: String,
}

#[derive(Subcommand, Debug)]
enum ExternalSqlHaCommand {
    SetPolicy(ExternalSqlHaPolicyArgs),
    RegisterNode(ExternalSqlHaRegisterNodeArgs),
    Plan(ExternalSqlDbArgs),
}

#[derive(Args, Debug)]
struct ExternalSqlHaPolicyArgs {
    #[arg(long)]
    db_uri: String,
    #[arg(long)]
    quorum: i64,
    #[arg(long)]
    min_ready: i64,
    #[arg(long, default_value_t = 1)]
    batch_size: i64,
    #[arg(long)]
    target_version: Option<String>,
}

#[derive(Args, Debug)]
struct ExternalSqlHaRegisterNodeArgs {
    #[arg(long)]
    db_uri: String,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    version: String,
    #[arg(long, default_value_t = true)]
    ready: bool,
}

#[derive(Subcommand, Debug)]
enum ExternalSqlJobCommand {
    Enqueue(ExternalSqlJobEnqueueArgs),
    List(ExternalSqlDbArgs),
}

#[derive(Args, Debug)]
struct ExternalSqlJobEnqueueArgs {
    #[arg(long)]
    db_uri: String,
    #[arg(long)]
    name: String,
}

#[derive(Args, Debug)]
struct ExternalSqlDbArgs {
    #[arg(long)]
    db_uri: String,
}

#[derive(Args, Debug)]
struct DemoArgs {
    #[arg(long)]
    workspace: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Simulace(SimulaceCommand::Generuj(args)) => {
            let profile = resolve_simulation_profile(
                &args.profil,
                args.extra_hostu,
                args.max_sluzeb_na_host,
                args.telemetrie_na_host,
                args.flow_repetitions,
            )?;
            simulation::generate_simulation_with_profile(
                &args.vystup,
                args.seed,
                args.nahodnych,
                &profile,
            )?;
            println!(
                "Simulacni prostredi bylo vygenerovano do: {}",
                args.vystup.display()
            );
        }
        Command::Beh(BehCommand::Spust(args)) => {
            let report = run_pipeline(args)?;
            println!(
                "Beh {} dokoncen. Report: {}",
                report.run.run_id,
                Path::new(&report.run.run_id).display()
            );
        }
        Command::Autopilot(AutopilotCommand::Spust(args)) => {
            let automation_report = run_autopilot(args)?;
            println!(
                "Autopilot dokoncen. Cykly={} coverage={:.2} identity={:.2}",
                automation_report.summary.cycles_total,
                automation_report.summary.tooling_coverage_ratio,
                automation_report.summary.service_identity_coverage_ratio
            );
        }
        Command::Monitor(MonitorCommand::Spust(args)) => {
            let continuous = args.continuous;
            let reports = run_monitor(args)?;
            if !continuous {
                println!("Monitor jsem dokoncil. Cykly={}", reports.len());
            }
        }
        Command::Overeni(OvereniCommand::Spust(args)) => {
            let verification_report = run_verification(args)?;
            println!(
                "Overeni dokonceno. Proslo {}/{} scenaru.",
                verification_report.summary.passed, verification_report.summary.total
            );
        }
        Command::Evaluace(EvaluaceCommand::Spust(args)) => {
            let evaluation_report = run_evaluation(args)?;
            println!(
                "Evaluace dokoncena. Precision {:.2}, recall {:.2}, F1 {:.2}, scenare {}/{}.",
                evaluation_report.summary.core_precision,
                evaluation_report.summary.core_recall,
                evaluation_report.summary.core_f1,
                evaluation_report.summary.scenarios_passed,
                evaluation_report.summary.scenarios_total
            );
        }
        Command::Server(ServerCommand::Spust(args)) => {
            let config_path = args
                .config
                .clone()
                .unwrap_or_else(|| args.workspace.join("bakula.toml"));
            let mut config = config::load_or_default(&config_path)?;
            config.workspace_root = args.workspace.to_string_lossy().to_string();
            config.host = args.host;
            config.port = args.port;
            if let Some(api_token_env) = args.api_token_env {
                config.security.api_token_env = Some(api_token_env);
            }
            if args.require_api_token {
                config.security.require_api_token = true;
            }
            config::validate(&config)?;
            let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(server::serve_with_config(addr, config))?;
        }
        Command::Ai(AiCommand::Diagnostika) => {
            println!("{}", serde_json::to_string_pretty(&ai::diagnose())?);
        }
        Command::Ai(AiCommand::Setup(args)) => {
            let diagnostic = ai::setup_ollama_model(&args.modelfile, args.pull)?;
            println!("{}", serde_json::to_string_pretty(&diagnostic)?);
        }
        Command::Ai(AiCommand::Modelfile(args)) => {
            let path = ai::write_modelfile(&args.vystup)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "modelfile": path,
                    "model": ai::SKOKY_MODEL,
                    "base_model": ai::SKOKY_BASE_MODEL
                }))?
            );
        }
        Command::Ai(AiCommand::Test(args)) => {
            let answer = ai::smoke_prompt(&args.prompt)?;
            println!("{answer}");
        }
        Command::Readiness(args) => {
            let report = readiness::assess_workspace(&args.workspace, args.require_api_token)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Config(ConfigCommand::Init(args)) => {
            let config = config::load_or_default(&args.path)?;
            println!(
                "Konfigurace je pripravena v {} (workspace_root={}, auth_required={}, max_runs={}).",
                args.path.display(),
                config.workspace_root,
                config.security.require_api_token,
                config.retention.max_runs
            );
        }
        Command::Config(ConfigCommand::Validate(args)) => {
            let config = config::load_or_default(&args.path)?;
            config::validate(&config)?;
            println!(
                "Konfigurace je validni: workspace_root={}, host={}, port={}, auth_required={}, max_runs={}, keep_raw={}.",
                config.workspace_root,
                config.host,
                config.port,
                config.security.require_api_token,
                config.retention.max_runs,
                config.retention.keep_raw
            );
        }
        Command::Platform(PlatformCommand::Init(args)) => {
            platform::init_database(&args.db)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "db": args.db,
                    "initialized": true
                }))?
            );
        }
        Command::Platform(PlatformCommand::User(PlatformUserCommand::Add(args))) => {
            platform::init_database(&args.db)?;
            let role = platform::Role::parse(&args.role)?;
            let user = platform::create_or_update_user(&args.db, &args.username, role)?;
            println!("{}", serde_json::to_string_pretty(&user)?);
        }
        Command::Platform(PlatformCommand::User(PlatformUserCommand::List(args))) => {
            let users = platform::list_users(&args.db)?;
            println!("{}", serde_json::to_string_pretty(&users)?);
        }
        Command::Platform(PlatformCommand::Token(PlatformTokenCommand::Issue(args))) => {
            platform::init_database(&args.db)?;
            let token = platform::issue_token(&args.db, &args.username, &args.name)?;
            println!("{}", serde_json::to_string_pretty(&token)?);
        }
        Command::Platform(PlatformCommand::Job(PlatformJobCommand::EnqueueScenario(args))) => {
            platform::init_database(&args.db)?;
            let spec = build_scenario_job_spec(&args)?;
            let job_id = platform::enqueue_job(
                &args.db,
                &args.nazev,
                &spec,
                args.schedule_interval_s,
                None,
            )?;
            if let Some(broker_uri) = &args.broker_uri {
                let broker_config = broker::RedisBrokerConfig::for_uri(broker_uri);
                broker::ensure_group(&broker_config)?;
                let _ = broker::publish_job(&broker_config, job_id)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "job_id": job_id,
                    "name": args.nazev,
                    "scheduled": args.schedule_interval_s.is_some(),
                }))?
            );
        }
        Command::Platform(PlatformCommand::Job(PlatformJobCommand::List(args))) => {
            let jobs = platform::list_jobs(&args.db)?;
            println!("{}", serde_json::to_string_pretty(&jobs)?);
        }
        Command::Platform(PlatformCommand::Worker(PlatformWorkerCommand::Run(args))) => {
            platform::init_database(&args.db)?;
            let display_name = args
                .display_name
                .clone()
                .unwrap_or_else(|| args.node_id.clone());
            let capabilities = vec![
                "pipeline".to_string(),
                "scheduler".to_string(),
                "cluster-lease".to_string(),
            ];
            if let Some(broker_uri) = &args.broker_uri {
                let broker_config = broker::RedisBrokerConfig::for_uri(broker_uri);
                platform::upsert_node_heartbeat(
                    &args.db,
                    &args.node_id,
                    &display_name,
                    &capabilities,
                )?;
                let message = broker::claim_one(&broker_config, &args.node_id, 500)?;
                let run_id = if let Some(message) = message {
                    if let Some(job) = platform::claim_job_by_id(
                        &args.db,
                        message.job_id,
                        &args.node_id,
                        args.job_lease_s,
                    )? {
                        match run_pipeline(spec_to_beh_args(job.spec)?) {
                            Ok(report) => {
                                platform::mark_job_succeeded(
                                    &args.db,
                                    job.id,
                                    &report.run.run_id,
                                    job.schedule_interval_s,
                                )?;
                                broker::ack(&broker_config, &message.stream_id)?;
                                Some(report.run.run_id)
                            }
                            Err(error) => {
                                platform::mark_job_failed(
                                    &args.db,
                                    job.id,
                                    &error.to_string(),
                                    job.schedule_interval_s,
                                )?;
                                broker::ack(&broker_config, &message.stream_id)?;
                                return Err(error);
                            }
                        }
                    } else {
                        broker::ack(&broker_config, &message.stream_id)?;
                        None
                    }
                } else {
                    None
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "node_id": args.node_id,
                        "run_id": run_id,
                        "broker_mode": true,
                    }))?
                );
            } else if args.once {
                let result = platform::worker_cycle(
                    &args.db,
                    &args.node_id,
                    &display_name,
                    &capabilities,
                    args.leader_ttl_s,
                    args.job_lease_s,
                    |spec| {
                        let args = spec_to_beh_args(spec).map_err(|error| error.to_string())?;
                        run_pipeline(args)
                            .map(|report| report.run.run_id)
                            .map_err(|error| error.to_string())
                    },
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "node_id": args.node_id,
                        "run_id": result,
                    }))?
                );
            } else {
                platform::worker_loop(
                    &args.db,
                    &args.node_id,
                    &display_name,
                    &capabilities,
                    args.leader_ttl_s,
                    args.job_lease_s,
                    |spec| {
                        let args = spec_to_beh_args(spec).map_err(|error| error.to_string())?;
                        run_pipeline(args)
                            .map(|report| report.run.run_id)
                            .map_err(|error| error.to_string())
                    },
                    Duration::from_secs(5),
                );
            }
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::SetPolicy(args))) => {
            platform::init_database(&args.db)?;
            let policy = platform::set_ha_policy(
                &args.db,
                args.quorum,
                args.min_ready,
                args.batch_size,
                args.target_version.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::RegisterNode(args))) => {
            platform::init_database(&args.db)?;
            let display_name = args
                .display_name
                .clone()
                .unwrap_or_else(|| args.node_id.clone());
            let node = platform::register_managed_node(
                &args.db,
                &args.node_id,
                &display_name,
                &["scheduler".to_string(), "worker".to_string()],
                &args.version,
                args.ready,
            )?;
            println!("{}", serde_json::to_string_pretty(&node)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::MarkReady(args))) => {
            let node = platform::mark_node_ready(&args.db, &args.node_id, &args.version)?;
            println!("{}", serde_json::to_string_pretty(&node)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::Plan(args))) => {
            let status = platform::ha_status(&args.db, None)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::Advance(args))) => {
            let selected = platform::advance_rollout(&args.db)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "selected": selected
                }))?
            );
        }
        Command::Platform(PlatformCommand::Status(args)) => {
            let snapshot = platform::snapshot(&args.db)?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Command::Broker(BrokerCommand::PublishDue(args)) => {
            let config = broker::RedisBrokerConfig::for_uri(&args.broker_uri);
            let published = broker::publish_due_jobs(&config, &args.db)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "published_job_ids": published,
                }))?
            );
        }
        Command::Broker(BrokerCommand::WorkerRun(args)) => {
            let config = broker::RedisBrokerConfig::for_uri(&args.broker_uri);
            let message = broker::claim_one(&config, &args.node_id, 500)?;
            println!("{}", serde_json::to_string_pretty(&message)?);
        }
        Command::ExternalSql(ExternalSqlCommand::Init(args)) => {
            external_sql::init_database(&args.db_uri)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "db_uri": args.db_uri,
                    "initialized": true
                }))?
            );
        }
        Command::ExternalSql(ExternalSqlCommand::User(ExternalSqlUserCommand::Add(args))) => {
            let role = platform::Role::parse(&args.role)?;
            let user = external_sql::create_or_update_user(&args.db_uri, &args.username, role)?;
            println!("{}", serde_json::to_string_pretty(&user)?);
        }
        Command::ExternalSql(ExternalSqlCommand::User(ExternalSqlUserCommand::List(args))) => {
            let users = external_sql::list_users(&args.db_uri)?;
            println!("{}", serde_json::to_string_pretty(&users)?);
        }
        Command::ExternalSql(ExternalSqlCommand::Token(ExternalSqlTokenCommand::Issue(args))) => {
            let token = external_sql::issue_token(&args.db_uri, &args.username, &args.name)?;
            println!("{}", serde_json::to_string_pretty(&token)?);
        }
        Command::ExternalSql(ExternalSqlCommand::Ha(ExternalSqlHaCommand::SetPolicy(args))) => {
            let policy = external_sql::set_ha_policy(
                &args.db_uri,
                args.quorum,
                args.min_ready,
                args.batch_size,
                args.target_version.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Command::ExternalSql(ExternalSqlCommand::Ha(ExternalSqlHaCommand::RegisterNode(args))) => {
            let display_name = args
                .display_name
                .clone()
                .unwrap_or_else(|| args.node_id.clone());
            let node = external_sql::register_managed_node(
                &args.db_uri,
                &args.node_id,
                &display_name,
                &["scheduler".to_string(), "worker".to_string()],
                &args.version,
                args.ready,
            )?;
            println!("{}", serde_json::to_string_pretty(&node)?);
        }
        Command::ExternalSql(ExternalSqlCommand::Ha(ExternalSqlHaCommand::Plan(args))) => {
            let status = external_sql::ha_status(&args.db_uri, None)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::ExternalSql(ExternalSqlCommand::Job(ExternalSqlJobCommand::Enqueue(args))) => {
            let job_id = external_sql::enqueue_job(&args.db_uri, &args.name)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "job_id": job_id,
                    "name": args.name,
                }))?
            );
        }
        Command::ExternalSql(ExternalSqlCommand::Job(ExternalSqlJobCommand::List(args))) => {
            let jobs = external_sql::list_jobs(&args.db_uri)?;
            println!("{}", serde_json::to_string_pretty(&jobs)?);
        }
        Command::ExternalSql(ExternalSqlCommand::Status(args)) => {
            let snapshot = external_sql::snapshot(&args.db_uri)?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Command::Demo(DemoCommand::E2e(args)) => {
            let sim_dir = args.workspace.join("simulace");
            simulation::generate_simulation(&sim_dir, 7, 0)?;

            let baseline = run_pipeline(BehArgs {
                workspace: args.workspace.clone(),
                nazev: "Zakladni scenar".to_string(),
                scope: vec!["192.168.56.0/24".parse()?],
                ports: vec![21, 22, 23, 80, 443, 8080],
                profile: "demo".to_string(),
                provider: "demo".to_string(),
                supplement_vulners: false,
                freeze: false,
                production: false,
                nmap_xml: Some(sim_dir.join("zakladni").join("nmap.xml")),
                nmap_followup_xml: None,
                suricata_eve: Some(sim_dir.join("zakladni").join("suricata").join("eve.json")),
                zeek_dir: Some(sim_dir.join("zakladni").join("zeek")),
                porovnat_s: None,
                spustit_nmap: false,
                hloubkove_overeni: false,
                web_fingerprint: false,
                web_checks: false,
                pentest: false,
                aggressive_pentest: false,
                httpx_bin: None,
                nuclei_bin: None,
                nuclei_templates: None,
                snmp_snapshot: None,
                librenms_snapshot: None,
                librenms_base_url: None,
                librenms_token_env: "LIBRENMS_TOKEN".to_string(),
                meraki_snapshot: None,
                meraki_network_id: None,
                meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
                meraki_timespan_seconds: 86400,
                unifi_snapshot: None,
                unifi_devices_url: None,
                unifi_clients_url: None,
                unifi_links_url: None,
                unifi_api_key_env: "UNIFI_API_KEY".to_string(),
                aruba_snapshot: None,
                aruba_base_url: None,
                aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
                aruba_site_id: None,
                omada_snapshot: None,
                omada_devices_url: None,
                omada_clients_url: None,
                omada_links_url: None,
                omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
                ntopng_snapshot: None,
                flow_snapshot: None,
                greenbone_report: None,
                wazuh_report: None,
                napalm_snapshot: None,
                netmiko_snapshot: None,
                scrapli_snapshot: None,
                urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
                abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
                disable_circl: true,
            })?;

            let changed = run_pipeline(BehArgs {
                workspace: args.workspace.clone(),
                nazev: "Zmenovy scenar".to_string(),
                scope: vec!["192.168.56.0/24".parse()?],
                ports: vec![21, 22, 23, 80, 443, 8080],
                profile: "demo".to_string(),
                provider: "demo".to_string(),
                supplement_vulners: false,
                freeze: false,
                production: false,
                nmap_xml: Some(sim_dir.join("zmena").join("nmap.xml")),
                nmap_followup_xml: None,
                suricata_eve: Some(sim_dir.join("zmena").join("suricata").join("eve.json")),
                zeek_dir: Some(sim_dir.join("zmena").join("zeek")),
                porovnat_s: Some(baseline.run.run_id.clone()),
                spustit_nmap: false,
                hloubkove_overeni: false,
                web_fingerprint: false,
                web_checks: false,
                pentest: false,
                aggressive_pentest: false,
                httpx_bin: None,
                nuclei_bin: None,
                nuclei_templates: None,
                snmp_snapshot: None,
                librenms_snapshot: None,
                librenms_base_url: None,
                librenms_token_env: "LIBRENMS_TOKEN".to_string(),
                meraki_snapshot: None,
                meraki_network_id: None,
                meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
                meraki_timespan_seconds: 86400,
                unifi_snapshot: None,
                unifi_devices_url: None,
                unifi_clients_url: None,
                unifi_links_url: None,
                unifi_api_key_env: "UNIFI_API_KEY".to_string(),
                aruba_snapshot: None,
                aruba_base_url: None,
                aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
                aruba_site_id: None,
                omada_snapshot: None,
                omada_devices_url: None,
                omada_clients_url: None,
                omada_links_url: None,
                omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
                ntopng_snapshot: None,
                flow_snapshot: None,
                greenbone_report: None,
                wazuh_report: None,
                napalm_snapshot: None,
                netmiko_snapshot: None,
                scrapli_snapshot: None,
                urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
                abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
                disable_circl: true,
            })?;

            println!("Demo E2E hotovo.");
            println!("Zakladni run_id: {}", baseline.run.run_id);
            println!("Zmenovy run_id:  {}", changed.run.run_id);
            println!(
                "Spusteni UI: {} server spust --workspace {}",
                current_exe_invocation(),
                args.workspace.display()
            );
        }
    }

    Ok(())
}

fn current_exe_invocation() -> String {
    env::current_exe()
        .map(|path| format!("\"{}\"", path.display()))
        .unwrap_or_else(|_| "bakula-program.exe".to_string())
}

fn run_autopilot(args: AutopilotArgs) -> anyhow::Result<automation::AutomationReport> {
    fs::create_dir_all(&args.run.workspace)?;
    let _ = automation::begin_runtime(&args.run.workspace, args.cycles.max(1), &args.run.nazev);
    let mut cycle_reports = Vec::new();
    let mut previous_run_id = None::<String>;

    for cycle in 1..=args.cycles.max(1) {
        let _ = automation::begin_cycle(
            &args.run.workspace,
            cycle,
            args.cycles.max(1),
            &args.run.nazev,
        );
        let mut run_args = args.run.clone();
        run_args.nazev = format!("{} / cyklus {}", run_args.nazev, cycle);
        run_args.porovnat_s = previous_run_id.clone();
        promote_autopilot_args(&mut run_args);
        let report = match run_pipeline(run_args) {
            Ok(report) => report,
            Err(error) => {
                let _ = automation::fail_runtime(
                    &args.run.workspace,
                    &format!("Autopilot selhal v cyklu {cycle}: {error}"),
                );
                return Err(error);
            }
        };
        let _ = automation::finish_cycle(&args.run.workspace, &report.run.run_id);
        previous_run_id = Some(report.run.run_id.clone());
        cycle_reports.push(report);
        if cycle < args.cycles && args.interval_s > 0 {
            thread::sleep(Duration::from_secs(args.interval_s));
        }
    }

    let automation_report = automation::build_automation_report(&cycle_reports);
    automation::save_automation_report(&args.run.workspace, &automation_report)
        .map_err(|error| anyhow::Error::new(error).context("Uložení autopilot reportu selhalo"))?;
    let _ = automation::complete_runtime(&args.run.workspace, &automation_report);
    Ok(automation_report)
}

fn run_monitor(args: MonitorArgs) -> anyhow::Result<Vec<RunReport>> {
    fs::create_dir_all(&args.run.workspace)?;
    let total_cycles = args.cycles.max(1);
    let mut reports = Vec::new();
    let mut previous_run_id = args.run.porovnat_s.clone();
    let mut cycle = 1usize;

    loop {
        if !args.continuous && cycle > total_cycles {
            break;
        }

        let mut run_args = args.run.clone();
        run_args.nazev = format!("{} / monitor {}", args.run.nazev, cycle);
        run_args.porovnat_s = if cycle == 1 {
            args.run.porovnat_s.clone()
        } else {
            previous_run_id.clone()
        };
        promote_monitor_args(&mut run_args);
        validate_monitor_args(&run_args)?;

        let report = run_pipeline(run_args)?;
        println!(
            "V monitoru jsem dokoncil cyklus {}: run_id={} udalosti={} nalezy={}",
            cycle, report.run.run_id, report.summary.events_total, report.summary.findings_total
        );
        previous_run_id = Some(report.run.run_id.clone());
        if !args.continuous {
            reports.push(report);
        }

        if !args.continuous && cycle >= total_cycles {
            break;
        }
        cycle = cycle.saturating_add(1);
        if args.interval_s > 0 {
            thread::sleep(Duration::from_secs(args.interval_s));
        }
    }

    Ok(reports)
}

fn promote_monitor_args(args: &mut BehArgs) {
    args.hloubkove_overeni = true;
    auto_enable_vulners(args);
    args.disable_circl = false;
}

fn promote_autopilot_args(args: &mut BehArgs) {
    args.hloubkove_overeni = true;
    auto_enable_web_tools(args);
    auto_enable_vulners(args);
    args.disable_circl = false;
}

fn prepare_pipeline_args(mut args: BehArgs) -> anyhow::Result<BehArgs> {
    if args.production {
        apply_production_profile(&mut args);
    }
    if args.aggressive_pentest {
        args.pentest = true;
    }
    validate_pipeline_args(&args)?;
    Ok(args)
}

fn apply_production_profile(args: &mut BehArgs) {
    if args.nmap_xml.is_none() {
        args.spustit_nmap = true;
    }
    if args.provider == "demo" {
        args.provider = "public".to_string();
    }
    args.hloubkove_overeni = true;
    args.pentest = true;
    auto_enable_web_tools(args);
    auto_enable_vulners(args);
    args.disable_circl = false;
}

fn auto_enable_vulners(args: &mut BehArgs) {
    if matches!(args.provider.as_str(), "nvd" | "public" | "auto") {
        args.supplement_vulners = true;
    }
}

fn auto_enable_web_tools(args: &mut BehArgs) {
    if can_resolve_tool(
        args.httpx_bin.as_deref(),
        "httpx.exe",
        &[
            args.workspace
                .join("tools")
                .join("projectdiscovery")
                .join("httpx")
                .join("httpx.exe"),
            paths::project_path(&["tools", "projectdiscovery", "httpx", "httpx.exe"]),
        ],
    ) {
        args.web_fingerprint = true;
    }
    if can_resolve_tool(
        args.nuclei_bin.as_deref(),
        "nuclei.exe",
        &[
            args.workspace
                .join("tools")
                .join("projectdiscovery")
                .join("nuclei")
                .join("nuclei.exe"),
            paths::project_path(&["tools", "projectdiscovery", "nuclei", "nuclei.exe"]),
        ],
    ) {
        args.web_checks = true;
    }
}

fn validate_monitor_args(args: &BehArgs) -> anyhow::Result<()> {
    if !has_passive_telemetry(args) {
        return Err(anyhow::anyhow!(
            "Monitorovací režim potřebuje pasivní zdroj: zadej --suricata-eve nebo --zeek-dir."
        ));
    }
    Ok(())
}

fn validate_pipeline_args(args: &BehArgs) -> anyhow::Result<()> {
    if args.scope.is_empty() {
        return Err(anyhow::anyhow!(
            "Musím dostat alespoň jeden --scope rozsah."
        ));
    }
    if args.nmap_xml.is_none() && !args.spustit_nmap {
        return Err(anyhow::anyhow!(
            "Je nutne zadat --nmap-xml nebo zapnout --spustit-nmap."
        ));
    }
    if args.spustit_nmap && args.ports.is_empty() {
        return Err(anyhow::anyhow!(
            "Pro aktivní Nmap běh potřebuji alespoň jeden port v --ports."
        ));
    }
    if let Some(path) = &args.nmap_xml {
        ensure_file_exists(path, "--nmap-xml")?;
    }
    if let Some(path) = &args.nmap_followup_xml {
        ensure_file_exists(path, "--nmap-followup-xml")?;
    }
    if let Some(path) = &args.suricata_eve {
        ensure_file_exists(path, "--suricata-eve")?;
    }
    if let Some(path) = &args.zeek_dir {
        ensure_dir_exists(path, "--zeek-dir")?;
    }
    if args.production && !has_passive_telemetry(args) {
        return Err(anyhow::anyhow!(
            "Produkční běh má kombinovat aktivní i pasivní analýzu, proto potřebuji --suricata-eve nebo --zeek-dir."
        ));
    }
    Ok(())
}

fn has_passive_telemetry(args: &BehArgs) -> bool {
    args.suricata_eve.is_some() || args.zeek_dir.is_some()
}

fn ensure_file_exists(path: &Path, label: &str) -> anyhow::Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{} ukazuje na soubor, který neexistuje: {}",
            label,
            path.display()
        ))
    }
}

fn ensure_dir_exists(path: &Path, label: &str) -> anyhow::Result<()> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{} ukazuje na složku, která neexistuje: {}",
            label,
            path.display()
        ))
    }
}

fn can_resolve_tool(explicit: Option<&Path>, file_name: &str, defaults: &[PathBuf]) -> bool {
    if let Some(path) = explicit {
        if path.is_file() {
            return true;
        }
    }
    if defaults.iter().any(|path| path.is_file()) {
        return true;
    }
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|path| path.join(file_name).is_file()))
        .unwrap_or(false)
}

fn resolve_simulation_profile(
    profile_name: &str,
    extra_hosts: Option<usize>,
    max_services_per_host: Option<usize>,
    telemetry_burst_per_host: Option<usize>,
    flow_repetitions: Option<usize>,
) -> anyhow::Result<simulation::SimulationScaleProfile> {
    let profile = simulation::SimulationScaleProfile::from_name(profile_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Neznámý profil simulace '{}'. Použij standard|large|enterprise.",
            profile_name
        )
    })?;
    Ok(profile.with_overrides(
        extra_hosts,
        max_services_per_host,
        telemetry_burst_per_host,
        flow_repetitions,
    ))
}

#[derive(Debug, Clone)]
struct MasAgentPlan {
    role: &'static str,
    priority: f64,
    budget_ms: u64,
    latency_hint_ms: u64,
}

#[derive(Debug, Clone)]
struct MasAgentMetric {
    role: &'static str,
    priority: f64,
    budget_ms: u64,
    latency_hint_ms: u64,
    queue_wait_ms: u64,
    runtime_ms: u64,
    sla_met: bool,
}

enum ParallelCollectorOutput {
    Context(context::ContextBundle),
    Lanes(lanes::LaneBundle),
    Passive(Vec<NormalizedEvent>),
}

fn round_metric(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn adaptive_priority(base: f64, latency_hint_ms: u64, max_hint_ms: u64) -> f64 {
    let normalized = if max_hint_ms == 0 {
        0.0
    } else {
        latency_hint_ms as f64 / max_hint_ms as f64
    };
    round_metric((base + normalized * 0.35).clamp(0.15, 1.5))
}

fn adaptive_budget_ms(latency_hint_ms: u64, base_budget_ms: u64) -> u64 {
    base_budget_ms
        .saturating_add(latency_hint_ms.saturating_mul(2))
        .clamp(600, 20_000)
}

fn estimate_context_latency_hint(args: &BehArgs) -> u64 {
    let mut latency_ms = 120_u64;
    latency_ms += 70 * u64::from(args.snmp_snapshot.is_some());
    latency_ms += 120 * u64::from(args.librenms_snapshot.is_some());
    latency_ms += 260 * u64::from(args.librenms_base_url.is_some());
    latency_ms += 130 * u64::from(args.meraki_snapshot.is_some());
    latency_ms += 270 * u64::from(args.meraki_network_id.is_some());
    latency_ms += 120 * u64::from(args.unifi_snapshot.is_some());
    latency_ms += 240
        * u64::from(
            args.unifi_devices_url.is_some()
                || args.unifi_clients_url.is_some()
                || args.unifi_links_url.is_some(),
        );
    latency_ms += 120 * u64::from(args.aruba_snapshot.is_some());
    latency_ms += 220 * u64::from(args.aruba_base_url.is_some());
    latency_ms += 110 * u64::from(args.omada_snapshot.is_some());
    latency_ms += 230
        * u64::from(
            args.omada_devices_url.is_some()
                || args.omada_clients_url.is_some()
                || args.omada_links_url.is_some(),
        );
    latency_ms
}

fn estimate_live_observer_latency_hint(args: &BehArgs) -> u64 {
    let mut latency_ms = 100_u64;
    latency_ms += 180 * u64::from(args.suricata_eve.is_some());
    latency_ms += 220 * u64::from(args.zeek_dir.is_some());
    latency_ms += 150 * u64::from(args.ntopng_snapshot.is_some());
    latency_ms += 140 * u64::from(args.flow_snapshot.is_some());
    latency_ms
}

fn estimate_correlator_latency_hint(hosts_total: usize, findings_total: usize) -> u64 {
    160_u64
        .saturating_add((hosts_total as u64).saturating_mul(8))
        .saturating_add((findings_total as u64).saturating_mul(12))
}

fn estimate_followup_latency_hint(raw_inventory_hosts: usize) -> u64 {
    140_u64.saturating_add((raw_inventory_hosts as u64).saturating_mul(18))
}

fn estimate_forensic_latency_hint(open_services: usize) -> u64 {
    180_u64.saturating_add((open_services as u64).saturating_mul(9))
}

fn estimate_pentest_latency_hint(open_services: usize, aggressive: bool) -> u64 {
    let per_service = if aggressive { 140 } else { 55 };
    220_u64.saturating_add((open_services as u64).saturating_mul(per_service))
}

fn compute_parallelism_ratio(total_runtime_ms: u64, wall_ms: u64, workers: usize) -> f64 {
    if wall_ms == 0 || workers == 0 {
        return 1.0;
    }
    round_metric((total_runtime_ms as f64 / (wall_ms as f64 * workers as f64)).clamp(0.0, 1.0))
}

fn run_pipeline(args: BehArgs) -> anyhow::Result<RunReport> {
    let args = prepare_pipeline_args(args)?;
    fs::create_dir_all(&args.workspace)?;
    let config_path = args.workspace.join("bakula.toml");
    let app_config = config::load_or_default(&config_path)?;
    let workspace = Workspace::open(&args.workspace)?;
    let run_id = report::build_run_id();
    let mut mas_agent_metrics = Vec::<MasAgentMetric>::new();

    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "planning",
            "Plánovač skládá pořadí kroků a připravuje rozsah běhu.",
        );
    }

    let start = Utc::now();
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "inventory",
            "Inventář sbírá základní síťové služby a identity.",
        );
    }
    let nmap_path = if let Some(path) = &args.nmap_xml {
        path.clone()
    } else if args.spustit_nmap {
        nmap::run_real_nmap(&args.workspace, &args.scope, &args.ports, &args.profile)?
    } else {
        return Err(anyhow::anyhow!(
            "Je nutne zadat --nmap-xml nebo zapnout --spustit-nmap."
        ));
    };

    let mut raw_inventory = nmap::parse_nmap_xml(&nmap_path)?;
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "followup",
            "Cílený follow-up zpřesňuje nejasné služby a hosty.",
        );
    }
    let followup_hint_ms = estimate_followup_latency_hint(raw_inventory.hosts.len());
    let followup_budget_ms = adaptive_budget_ms(followup_hint_ms, 900);
    let followup_priority = adaptive_priority(0.68, followup_hint_ms, 1_500);
    let followup_started_at = Instant::now();
    let followup_scan = if let Some(path) = &args.nmap_followup_xml {
        Some(nmap::FollowupExecution {
            output_path: path.clone(),
            targeted_hosts: 0,
            targeted_ports: 0,
        })
    } else if args.spustit_nmap && args.nmap_xml.is_none() {
        nmap::run_targeted_followup_nmap(&args.workspace, &raw_inventory, &args.profile)?
    } else {
        None
    };
    let followup_scan = if let Some(followup) = followup_scan {
        let followup_inventory = nmap::parse_nmap_xml(&followup.output_path)?;
        let resolved_followup = nmap::FollowupExecution {
            output_path: followup.output_path.clone(),
            targeted_hosts: if followup.targeted_hosts == 0 {
                followup_inventory.hosts.len()
            } else {
                followup.targeted_hosts
            },
            targeted_ports: if followup.targeted_ports == 0 {
                followup_inventory
                    .hosts
                    .iter()
                    .flat_map(|host| host.services.iter().map(|service| service.port))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            } else {
                followup.targeted_ports
            },
        };
        raw_inventory = nmap::merge_followup_inventory(raw_inventory, followup_inventory);
        Some(resolved_followup)
    } else {
        None
    };
    let followup_runtime_ms = followup_started_at.elapsed().as_millis() as u64;
    mas_agent_metrics.push(MasAgentMetric {
        role: "followup",
        priority: followup_priority,
        budget_ms: followup_budget_ms,
        latency_hint_ms: followup_hint_ms,
        queue_wait_ms: 0,
        runtime_ms: followup_runtime_ms,
        sla_met: followup_runtime_ms <= followup_budget_ms,
    });
    let provider = vuln::build_provider(
        &args.workspace,
        &args.provider,
        args.supplement_vulners,
        args.freeze,
    )
    .map_err(|error| anyhow::Error::new(error).context("Nelze inicializovat provider"))?;
    let web_config = webscan::WebScanConfig {
        enable_httpx: args.web_fingerprint || args.web_checks,
        enable_nuclei: args.web_checks,
        httpx_bin: args.httpx_bin.clone(),
        nuclei_bin: args.nuclei_bin.clone(),
        nuclei_templates_dir: args.nuclei_templates.clone(),
    };
    let mut hosts = report::normalize_inventory(raw_inventory.clone());
    cpe::enrich_services_with_cpe(&mut hosts, &args.workspace.join("data"))?;
    vuln::enrich_with_vulnerabilities(&mut hosts, provider.as_ref())
        .map_err(|error| anyhow::Error::new(error).context("Obohaceni o zranitelnosti selhalo"))?;
    let mut web_artifacts =
        webscan::enrich_http_services(&mut hosts, &args.workspace, &run_id, &web_config).map_err(
            |error| anyhow::Error::new(error).context("Web fingerprinting / web checks selhaly"),
        )?;
    report::score_services(&mut hosts);
    let open_services_total = hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .filter(|service| service.port_state == "open")
        .count();
    let forensic_hint_ms = estimate_forensic_latency_hint(open_services_total);
    let forensic_budget_ms = adaptive_budget_ms(forensic_hint_ms, 1_200);
    let forensic_priority = adaptive_priority(0.74, forensic_hint_ms, 1_900);
    let forensic_started_at = Instant::now();

    let forensic_scan = if args.hloubkove_overeni && args.spustit_nmap {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "forensic",
            "Forenzní vrstva spouští hlubší ověření prioritních cílů.",
        );
        nmap::run_forensic_followup_nmap(&args.workspace, &hosts, &args.profile)?
    } else {
        None
    };
    let forensic_scan = if let Some(forensic) = forensic_scan {
        let forensic_inventory = nmap::parse_nmap_xml(&forensic.output_path)?;
        let resolved_forensic = nmap::FollowupExecution {
            output_path: forensic.output_path.clone(),
            targeted_hosts: if forensic.targeted_hosts == 0 {
                forensic_inventory.hosts.len()
            } else {
                forensic.targeted_hosts
            },
            targeted_ports: if forensic.targeted_ports == 0 {
                forensic_inventory
                    .hosts
                    .iter()
                    .flat_map(|host| host.services.iter().map(|service| service.port))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            } else {
                forensic.targeted_ports
            },
        };
        raw_inventory = nmap::merge_followup_inventory(raw_inventory, forensic_inventory);
        hosts = report::normalize_inventory(raw_inventory.clone());
        cpe::enrich_services_with_cpe(&mut hosts, &args.workspace.join("data"))?;
        vuln::enrich_with_vulnerabilities(&mut hosts, provider.as_ref()).map_err(|error| {
            anyhow::Error::new(error).context("Forenzní obohacení o zranitelnosti selhalo")
        })?;
        web_artifacts =
            webscan::enrich_http_services(&mut hosts, &args.workspace, &run_id, &web_config)
                .map_err(|error| {
                    anyhow::Error::new(error)
                        .context("Forenzní web fingerprinting / web checks selhaly")
                })?;
        Some(resolved_forensic)
    } else {
        None
    };
    let forensic_runtime_ms = forensic_started_at.elapsed().as_millis() as u64;
    mas_agent_metrics.push(MasAgentMetric {
        role: "forensic",
        priority: forensic_priority,
        budget_ms: forensic_budget_ms,
        latency_hint_ms: forensic_hint_ms,
        queue_wait_ms: 0,
        runtime_ms: forensic_runtime_ms,
        sla_met: forensic_runtime_ms <= forensic_budget_ms,
    });

    let pentest_hint_ms = if args.pentest {
        estimate_pentest_latency_hint(open_services_total, args.aggressive_pentest)
    } else {
        0
    };
    let pentest_budget_ms = adaptive_budget_ms(pentest_hint_ms, 1_600);
    let pentest_priority = adaptive_priority(
        if args.aggressive_pentest { 0.96 } else { 0.82 },
        pentest_hint_ms,
        if args.aggressive_pentest {
            2_400
        } else {
            1_600
        },
    );
    let pentest_started_at = Instant::now();
    let pentest_artifacts = pentest::run_internal_pentest(
        &mut hosts,
        &pentest::PentestConfig {
            enabled: args.pentest,
            aggressive: args.aggressive_pentest,
            timeout_ms: if args.aggressive_pentest {
                1_800
            } else {
                1_200
            },
        },
    )
    .map_err(|error| anyhow::Error::new(error).context("Interní pentest vrstva selhala"))?;
    let pentest_runtime_ms = pentest_started_at.elapsed().as_millis() as u64;
    if args.pentest {
        mas_agent_metrics.push(MasAgentMetric {
            role: if args.aggressive_pentest {
                "aggressive-pentest"
            } else {
                "internal-pentest"
            },
            priority: pentest_priority,
            budget_ms: pentest_budget_ms,
            latency_hint_ms: pentest_hint_ms,
            queue_wait_ms: 0,
            runtime_ms: pentest_runtime_ms,
            sla_met: pentest_runtime_ms <= pentest_budget_ms,
        });
    }

    let end = Utc::now();
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "context",
            "Autorizované adaptéry skládají topologii, aktiva a sousedy.",
        );
    }
    let context_config = context::ContextConfig {
        snmp_snapshot: args.snmp_snapshot.clone(),
        librenms_snapshot: args.librenms_snapshot.clone(),
        librenms_base_url: args.librenms_base_url.clone(),
        librenms_token_env: args.librenms_token_env.clone(),
        meraki_snapshot: args.meraki_snapshot.clone(),
        meraki_api_key_env: args.meraki_api_key_env.clone(),
        meraki_network_id: args.meraki_network_id.clone(),
        meraki_timespan_seconds: args.meraki_timespan_seconds,
        unifi_snapshot: args.unifi_snapshot.clone(),
        unifi_devices_url: args.unifi_devices_url.clone(),
        unifi_clients_url: args.unifi_clients_url.clone(),
        unifi_links_url: args.unifi_links_url.clone(),
        unifi_api_key_env: args.unifi_api_key_env.clone(),
        aruba_snapshot: args.aruba_snapshot.clone(),
        aruba_base_url: args.aruba_base_url.clone(),
        aruba_token_env: args.aruba_token_env.clone(),
        aruba_site_id: args.aruba_site_id.clone(),
        omada_snapshot: args.omada_snapshot.clone(),
        omada_devices_url: args.omada_devices_url.clone(),
        omada_clients_url: args.omada_clients_url.clone(),
        omada_links_url: args.omada_links_url.clone(),
        omada_access_token_env: args.omada_access_token_env.clone(),
    };
    let lane_config = lanes::LaneConfig {
        ntopng_snapshot: args.ntopng_snapshot.clone(),
        flow_snapshot: args.flow_snapshot.clone(),
        greenbone_report: args.greenbone_report.clone(),
        wazuh_report: args.wazuh_report.clone(),
        napalm_snapshot: args.napalm_snapshot.clone(),
        netmiko_snapshot: args.netmiko_snapshot.clone(),
        scrapli_snapshot: args.scrapli_snapshot.clone(),
    };
    let passive_window = report::determine_passive_window(start, end);
    let passive_sources = passive::PassiveSources {
        suricata_eve: args.suricata_eve.clone(),
        zeek_dir: args.zeek_dir.clone(),
    };
    let context_hint_ms = estimate_context_latency_hint(&args);
    let live_observer_hint_ms = estimate_live_observer_latency_hint(&args);
    let correlator_prep_hint_ms = estimate_correlator_latency_hint(
        hosts.len(),
        hosts.iter().map(|host| host.services.len()).sum(),
    );
    let max_hint_ms = context_hint_ms
        .max(live_observer_hint_ms)
        .max(correlator_prep_hint_ms)
        .max(1);
    let mut parallel_plans = vec![
        MasAgentPlan {
            role: "context-fusion",
            priority: adaptive_priority(0.84, context_hint_ms, max_hint_ms),
            budget_ms: adaptive_budget_ms(context_hint_ms, 1_000),
            latency_hint_ms: context_hint_ms,
        },
        MasAgentPlan {
            role: "correlator-prep",
            priority: adaptive_priority(0.80, correlator_prep_hint_ms, max_hint_ms),
            budget_ms: adaptive_budget_ms(correlator_prep_hint_ms, 950),
            latency_hint_ms: correlator_prep_hint_ms,
        },
        MasAgentPlan {
            role: "live-observer",
            priority: adaptive_priority(0.88, live_observer_hint_ms, max_hint_ms),
            budget_ms: adaptive_budget_ms(live_observer_hint_ms, 950),
            latency_hint_ms: live_observer_hint_ms,
        },
    ];
    parallel_plans.sort_by(|left, right| {
        right
            .priority
            .partial_cmp(&left.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let hosts_ref = &hosts;
    let context_config_ref = &context_config;
    let lane_config_ref = &lane_config;
    let passive_sources_ref = &passive_sources;
    let scope_ref = &args.scope;
    let parallel_started_at = Instant::now();
    let (context_bundle, lane_bundle, passive_events, parallel_metrics) = thread::scope(|scope| {
        let scheduler_started_at = Instant::now();
        let mut handles = Vec::new();
        for plan in parallel_plans {
            let queue_wait_ms = scheduler_started_at.elapsed().as_millis() as u64;
            let hosts_ref = hosts_ref;
            let context_config_ref = context_config_ref;
            let lane_config_ref = lane_config_ref;
            let passive_sources_ref = passive_sources_ref;
            let scope_ref = scope_ref;
            let handle = scope.spawn(move || {
                let started_at = Instant::now();
                let output = match plan.role {
                    "context-fusion" => ParallelCollectorOutput::Context(
                        context::collect_context(hosts_ref, context_config_ref).map_err(
                            |error| {
                                anyhow::Error::new(error)
                                    .context("Načtení autorizovaných síťových zdrojů selhalo")
                            },
                        )?,
                    ),
                    "correlator-prep" => ParallelCollectorOutput::Lanes(
                        lanes::collect_lanes(hosts_ref, lane_config_ref).map_err(|error| {
                            anyhow::Error::new(error).context("Načtení live/audit lanes selhalo")
                        })?,
                    ),
                    _ => ParallelCollectorOutput::Passive(
                        passive::load_and_normalize(
                            passive_sources_ref,
                            scope_ref,
                            passive_window.start,
                            passive_window.end,
                            hosts_ref,
                        )
                        .map_err(|error| {
                            anyhow::Error::new(error).context("Pasivni import selhal")
                        })?,
                    ),
                };
                let runtime_ms = started_at.elapsed().as_millis() as u64;
                Ok::<_, anyhow::Error>((
                    MasAgentMetric {
                        role: plan.role,
                        priority: plan.priority,
                        budget_ms: plan.budget_ms,
                        latency_hint_ms: plan.latency_hint_ms,
                        queue_wait_ms,
                        runtime_ms,
                        sla_met: runtime_ms <= plan.budget_ms,
                    },
                    output,
                ))
            });
            handles.push(handle);
        }

        let mut context_bundle = None;
        let mut lane_bundle = None;
        let mut passive_events = None;
        let mut metrics = Vec::new();
        for handle in handles {
            let (metric, output) = handle
                .join()
                .map_err(|_| anyhow::anyhow!("MAS worker skončil panicem"))??;
            metrics.push(metric);
            match output {
                ParallelCollectorOutput::Context(value) => context_bundle = Some(value),
                ParallelCollectorOutput::Lanes(value) => lane_bundle = Some(value),
                ParallelCollectorOutput::Passive(value) => passive_events = Some(value),
            }
        }

        Ok::<_, anyhow::Error>((
            context_bundle.ok_or_else(|| anyhow::anyhow!("Context worker nevrátil výstup"))?,
            lane_bundle.ok_or_else(|| anyhow::anyhow!("Lane worker nevrátil výstup"))?,
            passive_events.ok_or_else(|| anyhow::anyhow!("Passive worker nevrátil výstup"))?,
            metrics,
        ))
    })?;
    let parallel_stage_wall_ms = parallel_started_at.elapsed().as_millis() as u64;
    let parallel_stage_workers = parallel_metrics.len();
    mas_agent_metrics.extend(parallel_metrics);

    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "passive",
            "Pasivní vrstva dokončila sběr toků a předává data ke korelaci.",
        );
    }

    let correlator_hint_ms = estimate_correlator_latency_hint(hosts.len(), 0);
    let correlator_budget_ms = adaptive_budget_ms(correlator_hint_ms, 1_100);
    let correlator_priority = adaptive_priority(0.92, correlator_hint_ms, 1_600);
    let correlator_started_at = Instant::now();
    let correlated =
        correlation::correlate_events(&hosts, passive_events, passive_window.time_window_s);
    let unmapped_events = report::attach_events(&mut hosts, correlated);
    report::score_services(&mut hosts);
    let correlator_runtime_ms = correlator_started_at.elapsed().as_millis() as u64;
    mas_agent_metrics.push(MasAgentMetric {
        role: "correlator",
        priority: correlator_priority,
        budget_ms: correlator_budget_ms,
        latency_hint_ms: correlator_hint_ms,
        queue_wait_ms: 0,
        runtime_ms: correlator_runtime_ms,
        sla_met: correlator_runtime_ms <= correlator_budget_ms,
    });
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "correlation",
            "Korelační vrstva spojuje nálezy, změny a doporučené kroky.",
        );
    }

    let mas_total_runtime_ms = mas_agent_metrics
        .iter()
        .map(|metric| metric.runtime_ms)
        .sum::<u64>();
    let mas_queue_wait_ms_avg = if mas_agent_metrics.is_empty() {
        0.0
    } else {
        round_metric(
            mas_agent_metrics
                .iter()
                .map(|metric| metric.queue_wait_ms as f64)
                .sum::<f64>()
                / mas_agent_metrics.len() as f64,
        )
    };
    let mas_agent_sla_ratio = if mas_agent_metrics.is_empty() {
        1.0
    } else {
        round_metric(
            mas_agent_metrics
                .iter()
                .filter(|metric| metric.sla_met)
                .count() as f64
                / mas_agent_metrics.len() as f64,
        )
    };
    let parallel_runtime_ms = mas_agent_metrics
        .iter()
        .filter(|metric| {
            metric.role == "context-fusion"
                || metric.role == "correlator-prep"
                || metric.role == "live-observer"
        })
        .map(|metric| metric.runtime_ms)
        .sum::<u64>();
    let mas_parallelism_ratio = compute_parallelism_ratio(
        parallel_runtime_ms,
        parallel_stage_wall_ms,
        parallel_stage_workers,
    );

    let mut report = report::build_report(
        &run_id,
        &args.nazev,
        start,
        end,
        args.scope.clone(),
        args.ports.clone(),
        &args.profile,
        &args.provider,
        if args.freeze { "freeze" } else { "live" },
        passive_window,
        report::build_source_metadata(
            if args.spustit_nmap { "live" } else { "replay" },
            &nmap_path,
            followup_scan.as_ref().map(|item| &item.output_path),
            forensic_scan.as_ref().map(|item| &item.output_path),
            args.suricata_eve.as_ref(),
            args.zeek_dir.as_ref(),
            args.snmp_snapshot.as_ref(),
            args.librenms_snapshot.as_ref(),
            args.librenms_base_url.as_deref(),
            args.meraki_snapshot.as_ref(),
            args.meraki_network_id.as_deref(),
            args.unifi_snapshot.as_ref(),
            args.aruba_snapshot.as_ref(),
            args.omada_snapshot.as_ref(),
            args.ntopng_snapshot.as_ref(),
            args.flow_snapshot.as_ref(),
            args.greenbone_report.as_ref(),
            args.wazuh_report.as_ref(),
            args.napalm_snapshot.as_ref(),
            args.netmiko_snapshot.as_ref(),
            args.scrapli_snapshot.as_ref(),
        ),
        hosts,
        unmapped_events,
    );
    report.summary.mas_parallelism_ratio = mas_parallelism_ratio;
    report.summary.mas_queue_wait_ms_avg = mas_queue_wait_ms_avg;
    report.summary.mas_agent_sla_ratio = mas_agent_sla_ratio;
    report.network_assets = context_bundle.network_assets;
    report.topology_edges = context_bundle.topology_edges;
    if report.network_assets.is_empty() {
        let (inferred_assets, inferred_edges) =
            report::infer_network_context_from_hosts(&report.hosts);
        report.network_assets = inferred_assets;
        if report.topology_edges.is_empty() {
            report.topology_edges = inferred_edges;
        }
    }
    report.summary.network_assets_total = report.network_assets.len();
    report.summary.wireless_clients_total = report
        .network_assets
        .iter()
        .filter(|asset| asset.asset_type == "wireless-client")
        .count();
    report.summary.topology_edges_total = report.topology_edges.len();
    report.monitoring_lanes = context_bundle.monitoring_lanes;
    report
        .monitoring_lanes
        .extend(lane_bundle.monitoring_lanes.into_iter());
    if let Some(followup) = &followup_scan {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:nmap-followup:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "nmap-followup".to_string(),
            title: "Cílený druhý průchod služeb".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Follow-up Nmap ověřil {} hostů a {} vybraných portů s hlubší identifikací.",
                followup.targeted_hosts, followup.targeted_ports
            ),
            evidence: vec![
                format!("xml={}", followup.output_path.display()),
                format!("hosts={}", followup.targeted_hosts),
                format!("ports={}", followup.targeted_ports),
            ],
            recommended_tools: vec![
                "nmap".to_string(),
                "httpx".to_string(),
                "nuclei".to_string(),
            ],
        });
    }
    if let Some(forensic) = &forensic_scan {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:nmap-forensic:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "nmap-forensic".to_string(),
            title: "Forenzní zpřesnění prioritních cílů".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Forenzní Nmap průchod ověřil {} hostů a {} prioritních portů se silnější sadou skriptů.",
                forensic.targeted_hosts, forensic.targeted_ports
            ),
            evidence: vec![
                format!("xml={}", forensic.output_path.display()),
                format!("hosts={}", forensic.targeted_hosts),
                format!("ports={}", forensic.targeted_ports),
            ],
            recommended_tools: vec![
                "nmap".to_string(),
                "httpx".to_string(),
                "nuclei".to_string(),
                "greenbone".to_string(),
            ],
        });
    }
    if args.web_fingerprint || args.web_checks {
        let web_target_count = report
            .hosts
            .iter()
            .flat_map(|host| host.services.iter())
            .filter(|service| {
                service.port_state == "open"
                    && matches!(service.port, 80 | 443 | 8080 | 8443 | 8843 | 8880 | 6789)
            })
            .count();
        let web_probe_lines = web_artifacts
            .httpx_output_jsonl
            .as_deref()
            .map(|output| {
                output
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
            })
            .unwrap_or(0);
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:web:httpx:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "httpx".to_string(),
            title: "HTTP fingerprinting".to_string(),
            status: if report.summary.web_probes_total > 0 {
                "ok"
            } else {
                "limited"
            }
            .to_string(),
            summary: if report.summary.web_probes_total > 0 {
                format!(
                    "HTTPX probe proběhl nad {web_target_count} službami a vrátil {} web probe záznamů.",
                    report.summary.web_probes_total
                )
            } else {
                format!(
                    "HTTPX byl spuštěný nad {web_target_count} HTTP službami, ale v tomto běhu žádná služba nevrátila čitelnou odpověď."
                )
            },
            evidence: vec![
                format!("targets={web_target_count}"),
                format!("web_probes={}", report.summary.web_probes_total),
                format!("raw_lines={web_probe_lines}"),
            ],
            recommended_tools: vec!["httpx".to_string()],
        });
    }
    if args.web_checks {
        let nuclei_lines = web_artifacts
            .nuclei_output_jsonl
            .as_deref()
            .map(|output| {
                output
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
            })
            .unwrap_or(0);
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:web:nuclei:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "nuclei".to_string(),
            title: "Řízené web checks".to_string(),
            status: if report.summary.active_checks_total > 0
                || report.summary.web_probes_total > 0
            {
                "ok"
            } else {
                "limited"
            }
            .to_string(),
            summary: if report.summary.active_checks_total > 0 {
                format!(
                    "Nuclei kontrola potvrdila {} aktivních nálezů.",
                    report.summary.active_checks_total
                )
            } else if report.summary.web_probes_total > 0 {
                "Nuclei kontrola proběhla nad odpovídajícími web službami a nepotvrdila aktivní web nález.".to_string()
            } else {
                "Nuclei nemělo odpovídající web cíl z httpx, proto zůstává aktivní web ověření neuzavřené.".to_string()
            },
            evidence: vec![
                format!("active_checks={}", report.summary.active_checks_total),
                format!("web_probes={}", report.summary.web_probes_total),
                format!("raw_lines={nuclei_lines}"),
            ],
            recommended_tools: vec!["nuclei".to_string()],
        });
    }
    if args.pentest {
        let mode = if args.aggressive_pentest {
            "aggressive"
        } else {
            "smart"
        };
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:pentest:internal:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "internal-pentest".to_string(),
            title: if args.aggressive_pentest {
                "Interní agresivnější pentest".to_string()
            } else {
                "Interní smart pentest".to_string()
            },
            status: if pentest_artifacts.active_checks_total > 0
                || pentest_artifacts.web_probes_total > 0
                || pentest_artifacts.tcp_reachable_total > 0
            {
                "ok"
            } else {
                "limited"
            }
            .to_string(),
            summary: format!(
                "Vestavěný pentest engine běžel v režimu {mode}: cíle {}, TCP dosažitelné {}, web odpovědi {}, aktivní nálezy {}.",
                pentest_artifacts.targets_total,
                pentest_artifacts.tcp_reachable_total,
                pentest_artifacts.web_probes_total,
                pentest_artifacts.active_checks_total
            ),
            evidence: vec![
                format!("mode={mode}"),
                format!("targets={}", pentest_artifacts.targets_total),
                format!("tcp_reachable={}", pentest_artifacts.tcp_reachable_total),
                format!("web_probes={}", pentest_artifacts.web_probes_total),
                format!("active_checks={}", pentest_artifacts.active_checks_total),
                format!(
                    "aggressive_checks={}",
                    pentest_artifacts.aggressive_checks_total
                ),
                "tool=bakula-internal-pentest".to_string(),
            ],
            recommended_tools: vec![
                "bakula-tcp-probe".to_string(),
                "bakula-http-prober".to_string(),
                "bakula-method-auditor".to_string(),
            ],
        });
    }
    if args.suricata_eve.is_some() {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:passive:suricata:{}", report.run.run_id),
            lane_type: "live".to_string(),
            source: "suricata".to_string(),
            title: "Suricata pasivní telemetry".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Suricata zdroj byl načten, korelovaných událostí v okně: {}.",
                report.summary.events_total
            ),
            evidence: vec![format!(
                "suricata={}",
                args.suricata_eve.as_ref().unwrap().display()
            )],
            recommended_tools: vec!["suricata".to_string(), "zeek".to_string()],
        });
    }
    if args.zeek_dir.is_some() {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:passive:zeek:{}", report.run.run_id),
            lane_type: "live".to_string(),
            source: "zeek".to_string(),
            title: "Zeek pasivní telemetry".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Zeek zdroj byl načten, korelovaných událostí v okně: {}.",
                report.summary.events_total
            ),
            evidence: vec![format!(
                "zeek={}",
                args.zeek_dir.as_ref().unwrap().display()
            )],
            recommended_tools: vec!["zeek".to_string(), "suricata".to_string()],
        });
    }
    let mut scheduler_agents = mas_agent_metrics.clone();
    scheduler_agents.sort_by(|left, right| {
        right
            .priority
            .partial_cmp(&left.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut scheduler_evidence = vec![
        format!("parallelism_ratio={mas_parallelism_ratio:.2}"),
        format!("queue_wait_ms_avg={mas_queue_wait_ms_avg:.2}"),
        format!("agent_sla_ratio={mas_agent_sla_ratio:.2}"),
        format!("total_runtime_ms={mas_total_runtime_ms}"),
        format!("parallel_stage_wall_ms={parallel_stage_wall_ms}"),
    ];
    scheduler_evidence.extend(scheduler_agents.iter().take(6).map(|metric| {
        format!(
            "agent={} priority={:.2} budget_ms={} wait_ms={} runtime_ms={} latency_hint_ms={}",
            metric.role,
            metric.priority,
            metric.budget_ms,
            metric.queue_wait_ms,
            metric.runtime_ms,
            metric.latency_hint_ms
        )
    }));
    report.monitoring_lanes.push(MonitoringLane {
        lane_id: format!("lane:mas:scheduler:{}", report.run.run_id),
        lane_type: "automation".to_string(),
        source: "mas-scheduler".to_string(),
        title: "Adaptivní scheduling agentů".to_string(),
        status: if mas_agent_sla_ratio >= 0.8 {
            "ok".to_string()
        } else {
            "limited".to_string()
        },
        summary: format!(
            "Scheduler přidělil dynamické priority a budgety. SLA {:.0} %, queue wait {:.0} ms, paralelismus {:.0} %.",
            mas_agent_sla_ratio * 100.0,
            mas_queue_wait_ms_avg,
            mas_parallelism_ratio * 100.0
        ),
        evidence: scheduler_evidence,
        recommended_tools: vec![
            "runtime-metrics".to_string(),
            "nmap".to_string(),
            "suricata".to_string(),
        ],
    });
    report
        .monitoring_lanes
        .sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    report
        .monitoring_lanes
        .dedup_by(|left, right| left.lane_id == right.lane_id);
    report.summary.monitoring_lanes_total = report.monitoring_lanes.len();
    report.summary.live_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "live")
        .count();
    report.summary.audit_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "audit")
        .count();

    if let Some(base_run_id) = args.porovnat_s.as_deref() {
        if let Ok(base_report) = workspace.load_report(base_run_id) {
            report.diff = Some(diff::build_diff(&base_report, &report));
        }
    }

    report.intel_matches = intel::collect_intel(
        &report,
        &intel::IntelConfig {
            urlhaus_auth_env: args.urlhaus_auth_env.clone(),
            abuseipdb_key_env: args.abuseipdb_key_env.clone(),
            circl_enabled: !args.disable_circl,
            osv_enabled: true,
        },
    )
    .unwrap_or_default();
    report.summary.intel_matches_total = report.intel_matches.len();
    if let Some(intel_lane) = intel::build_public_intel_lane(&report) {
        report.monitoring_lanes.push(intel_lane);
    }
    report.findings = findings::generate_findings(&report);
    report.findings.extend(lane_bundle.findings);
    report
        .findings
        .sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    report
        .findings
        .dedup_by(|left, right| left.finding_id == right.finding_id);
    report.summary.findings_total = report.findings.len();
    report.summary.audit_findings_total = report
        .findings
        .iter()
        .filter(|item| {
            item.finding_type.starts_with("greenbone_")
                || item.finding_type.starts_with("wazuh_")
                || item.finding_type.contains("config_issue")
        })
        .count();
    let validation_bundle = validation::build_validation_bundle(&report);
    report.monitoring_lanes.extend(validation_bundle.lanes);
    report
        .monitoring_lanes
        .sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    report
        .monitoring_lanes
        .dedup_by(|left, right| left.lane_id == right.lane_id);
    report.summary.monitoring_lanes_total = report.monitoring_lanes.len();
    report.summary.live_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "live")
        .count();
    report.summary.audit_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "audit")
        .count();
    let consensus_snapshot = automation::build_consensus_snapshot(&report);
    report.summary.mas_consensus_score = consensus_snapshot.weighted_score;
    report.summary.mas_consensus_state = consensus_snapshot.state.clone();
    report.monitoring_lanes.push(MonitoringLane {
        lane_id: format!("lane:mas:consensus:{}", report.run.run_id),
        lane_type: "automation".to_string(),
        source: "mas-consensus".to_string(),
        title: "Confidence-weighted consensus".to_string(),
        status: if consensus_snapshot.state == "strong" {
            "ok".to_string()
        } else if consensus_snapshot.state == "review" {
            "limited".to_string()
        } else {
            "pending".to_string()
        },
        summary: format!(
            "Konsenzus followup/forensic/correlator = {:.0} % ({})",
            consensus_snapshot.weighted_score * 100.0,
            consensus_snapshot.state
        ),
        evidence: consensus_snapshot.evidence.clone(),
        recommended_tools: vec![
            "nmap".to_string(),
            "correlation".to_string(),
            "triage".to_string(),
        ],
    });
    report.triage_actions = triage::build_triage_actions(&report);
    report.triage_actions.extend(validation_bundle.actions);
    if consensus_snapshot.weighted_score < 0.55 {
        report.triage_actions.push(TriageAction {
            action_id: format!("action:mas-consensus-review:{}", report.run.run_id),
            action_type: "mas_consensus_review".to_string(),
            title: "Spustit manuální review nízkého MAS konsenzu".to_string(),
            priority: Severity::High,
            rationale: "Konsenzus mezi followup/forensic/correlator klesl pod bezpečný práh. Nejprve ověř přesnost identity služeb a forenzních důkazů.".to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec![
                "nmap-followup".to_string(),
                "nmap-forensic".to_string(),
                "diff".to_string(),
            ],
            evidence: consensus_snapshot.evidence.clone(),
        });
    }
    let decision_bundle = decision::build_decision_bundle(&report);
    report.triage_actions.extend(decision_bundle.actions);
    report.monitoring_lanes.extend(decision_bundle.lanes);
    report
        .triage_actions
        .sort_by(|left, right| right.priority.cmp(&left.priority));
    report
        .triage_actions
        .dedup_by(|left, right| left.action_id == right.action_id);
    report.summary.triage_actions_total = report.triage_actions.len();
    let automation_insights = automation::derive_insights(&report);
    report
        .monitoring_lanes
        .extend(automation_insights.agent_lanes.clone());
    report
        .monitoring_lanes
        .sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    report
        .monitoring_lanes
        .dedup_by(|left, right| left.lane_id == right.lane_id);
    report.summary.monitoring_lanes_total = report.monitoring_lanes.len();
    report.summary.live_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "live")
        .count();
    report.summary.audit_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "audit")
        .count();
    report.summary.automation_agents_total = automation_insights.automation_agents_total;
    report.summary.automation_rounds_total = automation_insights.automation_rounds_total;
    report.summary.forensic_targets_total = automation_insights.forensic_targets_total;
    report.summary.realtime_sources_total = automation_insights.realtime_sources_total;
    report.summary.service_identity_high_confidence_total =
        automation_insights.service_identity_high_confidence_total;
    report.summary.service_identity_coverage_ratio =
        automation_insights.service_identity_coverage_ratio;
    report.summary.tooling_coverage_ratio = automation_insights.tooling_coverage_ratio;
    report.summary.mas_parallelism_ratio = automation_insights.mas_parallelism_ratio;
    report.summary.mas_queue_wait_ms_avg = automation_insights.mas_queue_wait_ms_avg;
    report.summary.mas_agent_sla_ratio = automation_insights.mas_agent_sla_ratio;
    report.summary.mas_consensus_score = automation_insights.mas_consensus_score;
    report.summary.mas_consensus_state = automation_insights.mas_consensus_state;
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "finalize",
            "Report se finalizuje a ukládá do workspace.",
        );
    }

    workspace.save_run(
        &report,
        &nmap_path,
        followup_scan.as_ref().map(|item| &item.output_path),
        forensic_scan.as_ref().map(|item| &item.output_path),
        args.suricata_eve.as_ref(),
        args.zeek_dir.as_ref(),
        web_artifacts.httpx_output_jsonl.as_deref(),
        web_artifacts.nuclei_output_jsonl.as_deref(),
        pentest_artifacts.output_jsonl.as_deref(),
        context_bundle.artifacts.snmp_snapshot_json.as_deref(),
        context_bundle.artifacts.librenms_snapshot_json.as_deref(),
        context_bundle.artifacts.meraki_snapshot_json.as_deref(),
        context_bundle.artifacts.unifi_snapshot_json.as_deref(),
        context_bundle.artifacts.aruba_snapshot_json.as_deref(),
        context_bundle.artifacts.omada_snapshot_json.as_deref(),
        lane_bundle.artifacts.ntopng_json.as_deref(),
        lane_bundle.artifacts.flow_json.as_deref(),
        lane_bundle.artifacts.greenbone_json.as_deref(),
        lane_bundle.artifacts.wazuh_json.as_deref(),
        lane_bundle.artifacts.napalm_json.as_deref(),
        lane_bundle.artifacts.netmiko_json.as_deref(),
        lane_bundle.artifacts.scrapli_json.as_deref(),
    )?;
    workspace.enforce_retention(app_config.retention.max_runs, app_config.retention.keep_raw)?;
    Ok(report)
}

fn run_verification(args: OvereniArgs) -> anyhow::Result<verification::VerificationReport> {
    fs::create_dir_all(&args.workspace)?;
    let scenarios = discover_scenario_fixtures(&args.scenare)?;
    if scenarios.is_empty() {
        return Err(anyhow::anyhow!(
            "Ve slozce {} nebyly nalezeny zadne scenare s manifest.json.",
            args.scenare.display()
        ));
    }

    let mut reports_by_scenario = BTreeMap::<String, RunReport>::new();
    let mut results = Vec::new();

    for scenario in scenarios {
        let base_report = scenario
            .manifest
            .compare_to
            .as_ref()
            .and_then(|key| reports_by_scenario.get(key))
            .cloned();
        let report = run_pipeline(build_replay_beh_args(
            args.workspace.clone(),
            &scenario,
            scenario
                .manifest
                .provider
                .clone()
                .unwrap_or_else(|| args.provider.clone()),
            args.freeze,
            base_report.as_ref().map(|report| report.run.run_id.clone()),
        ))?;

        let result = verification::validate_scenario(
            &scenario.key,
            &scenario.manifest,
            &report,
            base_report.as_ref(),
        );
        reports_by_scenario.insert(scenario.key, report);
        results.push(result);
    }

    let verification_report = verification::build_verification_report(&args.provider, results);
    let path = verification::save_verification_report(&args.workspace, &verification_report)
        .map_err(|error| anyhow::Error::new(error).context("Nelze ulozit verifikacni report"))?;
    println!("Verifikacni report: {}", path.display());
    Ok(verification_report)
}

#[derive(Debug, Clone)]
struct ScenarioFixture {
    key: String,
    dir: PathBuf,
    manifest: verification::ScenarioManifest,
}

#[derive(Debug, Clone)]
struct ScenarioGroup {
    root_key: String,
    scenarios: Vec<ScenarioFixture>,
}

#[derive(Debug)]
struct ScenarioExecution {
    verification: verification::ScenarioVerification,
    metrics: evaluation::ScenarioEvalMetrics,
}

fn run_evaluation(args: EvaluaceArgs) -> anyhow::Result<evaluation::EvaluationReport> {
    fs::create_dir_all(&args.workspace)?;
    let scenarios_root = if let Some(path) = &args.scenare {
        path.clone()
    } else {
        let generated = args.workspace.join("scenarios-generated");
        let profile = resolve_simulation_profile(
            &args.profil,
            args.extra_hostu,
            args.max_sluzeb_na_host,
            args.telemetrie_na_host,
            args.flow_repetitions,
        )?;
        simulation::generate_simulation_with_profile(
            &generated,
            args.seed,
            args.nahodnych,
            &profile,
        )?;
        generated
    };
    let scenarios = discover_scenario_fixtures(&scenarios_root)?;
    if scenarios.is_empty() {
        return Err(anyhow::anyhow!(
            "Ve slozce {} nebyly nalezeny zadne scenare s manifest.json.",
            scenarios_root.display()
        ));
    }

    let tracked_core_types = scenarios
        .iter()
        .flat_map(|scenario| {
            scenario
                .manifest
                .expectations
                .required_finding_types
                .iter()
                .cloned()
        })
        .collect::<BTreeSet<_>>();
    let groups = build_scenario_groups(&scenarios)?;
    let worker_count = args.workers.max(1).min(groups.len().max(1));
    let assignments = assign_groups_to_workers(groups, worker_count);

    let mut handles = Vec::new();
    for (index, worker_groups) in assignments.into_iter().enumerate() {
        let provider = args.provider.clone();
        let tracked_core_types = tracked_core_types.clone();
        let worker_workspace = args
            .workspace
            .join("evaluation-workers")
            .join(format!("worker-{:02}", index + 1));
        let freeze = args.freeze;
        handles.push(thread::spawn(
            move || -> anyhow::Result<Vec<ScenarioExecution>> {
                prepare_worker_workspace(&worker_workspace)?;
                let mut outputs = Vec::new();
                for group in worker_groups {
                    let mut reports_by_scenario = BTreeMap::<String, RunReport>::new();
                    for scenario in group.scenarios {
                        let base_report = scenario
                            .manifest
                            .compare_to
                            .as_ref()
                            .and_then(|key| reports_by_scenario.get(key))
                            .cloned();
                        let report = run_pipeline(build_replay_beh_args(
                            worker_workspace.clone(),
                            &scenario,
                            scenario
                                .manifest
                                .provider
                                .clone()
                                .unwrap_or_else(|| provider.clone()),
                            freeze,
                            base_report.as_ref().map(|report| report.run.run_id.clone()),
                        ))?;
                        let verification = verification::validate_scenario(
                            &scenario.key,
                            &scenario.manifest,
                            &report,
                            base_report.as_ref(),
                        );
                        let metrics = evaluation::scenario_metrics(
                            &scenario.key,
                            &scenario.manifest,
                            &report,
                            &verification,
                            &tracked_core_types,
                        );
                        reports_by_scenario.insert(scenario.key.clone(), report);
                        outputs.push(ScenarioExecution {
                            verification,
                            metrics,
                        });
                    }
                }
                Ok(outputs)
            },
        ));
    }

    let mut verifications = Vec::new();
    let mut metrics = Vec::new();
    for handle in handles {
        let worker_output = handle
            .join()
            .map_err(|_| anyhow::anyhow!("Eval worker skoncil panicem"))??;
        for item in worker_output {
            verifications.push(item.verification);
            metrics.push(item.metrics);
        }
    }
    verifications.sort_by(|left, right| left.scenario_key.cmp(&right.scenario_key));

    let verification_report =
        verification::build_verification_report(&args.provider, verifications);
    let verification_path =
        verification::save_verification_report(&args.workspace, &verification_report).map_err(
            |error| anyhow::Error::new(error).context("Nelze ulozit verifikacni report z evaluace"),
        )?;
    let evaluation_report = evaluation::build_evaluation_report(
        args.seed,
        args.nahodnych,
        worker_count,
        &args.provider,
        tracked_core_types,
        metrics,
    );
    let evaluation_path =
        evaluation::save_evaluation_report(&args.workspace, &evaluation_report)
            .map_err(|error| anyhow::Error::new(error).context("Nelze ulozit evaluacni report"))?;
    println!("Verifikacni report: {}", verification_path.display());
    println!("Evaluacni report: {}", evaluation_path.display());
    Ok(evaluation_report)
}

fn discover_scenario_fixtures(root: &Path) -> anyhow::Result<Vec<ScenarioFixture>> {
    let scenario_dirs = verification::discover_scenarios(root)
        .map_err(|error| anyhow::Error::new(error).context("Nelze nacist scenare"))?;
    let mut scenarios = Vec::new();
    for scenario_dir in scenario_dirs {
        let key = scenario_key_from_dir(&scenario_dir)?;
        let manifest = verification::load_manifest(&scenario_dir.join("manifest.json"))
            .map_err(|error| anyhow::Error::new(error).context("Manifest scenare je neplatny"))?;
        scenarios.push(ScenarioFixture {
            key,
            dir: scenario_dir,
            manifest,
        });
    }
    scenarios.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(scenarios)
}

fn scenario_key_from_dir(path: &Path) -> anyhow::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|value| value.to_string())
        .ok_or_else(|| anyhow::anyhow!("Neplatny nazev scenare: {}", path.display()))
}

fn build_replay_beh_args(
    workspace: PathBuf,
    scenario: &ScenarioFixture,
    provider: String,
    freeze: bool,
    compare_run_id: Option<String>,
) -> BehArgs {
    BehArgs {
        workspace,
        nazev: scenario.manifest.nazev.clone(),
        scope: scenario.manifest.scope.clone(),
        ports: scenario.manifest.ports.clone(),
        profile: scenario.manifest.profile.clone(),
        provider,
        supplement_vulners: false,
        freeze,
        production: false,
        nmap_xml: Some(scenario.dir.join("nmap.xml")),
        nmap_followup_xml: None,
        suricata_eve: existing_file(scenario.dir.join("suricata").join("eve.json")),
        zeek_dir: existing_dir(scenario.dir.join("zeek")),
        porovnat_s: compare_run_id,
        spustit_nmap: false,
        hloubkove_overeni: false,
        web_fingerprint: false,
        web_checks: false,
        pentest: false,
        aggressive_pentest: false,
        httpx_bin: None,
        nuclei_bin: None,
        nuclei_templates: None,
        snmp_snapshot: None,
        librenms_snapshot: None,
        librenms_base_url: None,
        librenms_token_env: "LIBRENMS_TOKEN".to_string(),
        meraki_snapshot: None,
        meraki_network_id: None,
        meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
        meraki_timespan_seconds: 86400,
        unifi_snapshot: None,
        unifi_devices_url: None,
        unifi_clients_url: None,
        unifi_links_url: None,
        unifi_api_key_env: "UNIFI_API_KEY".to_string(),
        aruba_snapshot: None,
        aruba_base_url: None,
        aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
        aruba_site_id: None,
        omada_snapshot: None,
        omada_devices_url: None,
        omada_clients_url: None,
        omada_links_url: None,
        omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
        ntopng_snapshot: None,
        flow_snapshot: None,
        greenbone_report: None,
        wazuh_report: None,
        napalm_snapshot: None,
        netmiko_snapshot: None,
        scrapli_snapshot: None,
        urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
        abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
        disable_circl: true,
    }
}

fn build_scenario_groups(scenarios: &[ScenarioFixture]) -> anyhow::Result<Vec<ScenarioGroup>> {
    let by_key = scenarios
        .iter()
        .cloned()
        .map(|scenario| (scenario.key.clone(), scenario))
        .collect::<BTreeMap<_, _>>();
    for scenario in scenarios {
        if let Some(compare_to) = &scenario.manifest.compare_to {
            if !by_key.contains_key(compare_to) {
                return Err(anyhow::anyhow!(
                    "Scenar {} odkazuje na chybejici compare_to {}.",
                    scenario.key,
                    compare_to
                ));
            }
        }
    }

    let mut children = BTreeMap::<String, Vec<String>>::new();
    let mut roots = Vec::new();
    for scenario in scenarios {
        if let Some(compare_to) = &scenario.manifest.compare_to {
            children
                .entry(compare_to.clone())
                .or_default()
                .push(scenario.key.clone());
        } else {
            roots.push(scenario.key.clone());
        }
    }
    for items in children.values_mut() {
        items.sort();
    }
    roots.sort();

    let mut visited = BTreeSet::new();
    let mut groups = Vec::new();
    for root in roots {
        if visited.contains(&root) {
            continue;
        }
        let mut ordered = Vec::new();
        collect_scenario_group(&root, &by_key, &children, &mut visited, &mut ordered)?;
        groups.push(ScenarioGroup {
            root_key: root,
            scenarios: ordered,
        });
    }
    for key in by_key.keys() {
        if visited.contains(key) {
            continue;
        }
        let mut ordered = Vec::new();
        collect_scenario_group(key, &by_key, &children, &mut visited, &mut ordered)?;
        groups.push(ScenarioGroup {
            root_key: key.clone(),
            scenarios: ordered,
        });
    }
    groups.sort_by(|left, right| left.root_key.cmp(&right.root_key));
    Ok(groups)
}

fn collect_scenario_group(
    key: &str,
    by_key: &BTreeMap<String, ScenarioFixture>,
    children: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    ordered: &mut Vec<ScenarioFixture>,
) -> anyhow::Result<()> {
    if !visited.insert(key.to_string()) {
        return Ok(());
    }
    let scenario = by_key
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Scenar {} nebyl nalezen.", key))?;
    ordered.push(scenario);
    if let Some(items) = children.get(key) {
        for child in items {
            collect_scenario_group(child, by_key, children, visited, ordered)?;
        }
    }
    Ok(())
}

fn assign_groups_to_workers(
    mut groups: Vec<ScenarioGroup>,
    workers: usize,
) -> Vec<Vec<ScenarioGroup>> {
    let worker_count = workers.max(1).min(groups.len().max(1));
    groups.sort_by(|left, right| {
        right
            .scenarios
            .len()
            .cmp(&left.scenarios.len())
            .then(left.root_key.cmp(&right.root_key))
    });
    let mut assignments = vec![Vec::new(); worker_count];
    let mut loads = vec![0usize; worker_count];
    for group in groups {
        let (target_index, _) = loads
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| **load)
            .expect("alespon jeden worker");
        loads[target_index] += group.scenarios.len();
        assignments[target_index].push(group);
    }
    assignments
}

fn prepare_worker_workspace(workspace: &Path) -> anyhow::Result<()> {
    if workspace.exists() {
        fs::remove_dir_all(workspace)?;
    }
    fs::create_dir_all(workspace)?;
    let config_path = workspace.join("bakula.toml");
    let mut app_config = AppConfig::default();
    app_config.workspace_root = workspace.to_string_lossy().to_string();
    app_config.retention.max_runs = 10_000;
    fs::write(&config_path, toml::to_string_pretty(&app_config)?)?;
    Ok(())
}

fn build_scenario_job_spec(
    args: &PlatformJobScenarioArgs,
) -> anyhow::Result<platform::PipelineJobSpec> {
    Ok(platform::PipelineJobSpec {
        workspace_root: args.workspace.to_string_lossy().to_string(),
        nazev: args.nazev.clone(),
        scope: args.scope.iter().map(ToString::to_string).collect(),
        ports: args.ports.clone(),
        profile: args.profile.clone(),
        provider: args.provider.clone(),
        supplement_vulners: false,
        freeze: false,
        nmap_xml: Some(
            args.scenario_dir
                .join("nmap.xml")
                .to_string_lossy()
                .to_string(),
        ),
        nmap_followup_xml: None,
        suricata_eve: existing_file(args.scenario_dir.join("suricata").join("eve.json"))
            .map(|item| item.to_string_lossy().to_string()),
        zeek_dir: existing_dir(args.scenario_dir.join("zeek"))
            .map(|item| item.to_string_lossy().to_string()),
        porovnat_s: None,
        spustit_nmap: false,
        web_fingerprint: false,
        web_checks: false,
        pentest: false,
        aggressive_pentest: false,
        httpx_bin: None,
        nuclei_bin: None,
        nuclei_templates: None,
        snmp_snapshot: None,
        librenms_snapshot: None,
        librenms_base_url: None,
        librenms_token_env: "LIBRENMS_TOKEN".to_string(),
        meraki_snapshot: None,
        meraki_network_id: None,
        meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
        meraki_timespan_seconds: 86400,
        unifi_snapshot: None,
        unifi_devices_url: None,
        unifi_clients_url: None,
        unifi_links_url: None,
        unifi_api_key_env: "UNIFI_API_KEY".to_string(),
        aruba_snapshot: None,
        aruba_base_url: None,
        aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
        aruba_site_id: None,
        omada_snapshot: None,
        omada_devices_url: None,
        omada_clients_url: None,
        omada_links_url: None,
        omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
        ntopng_snapshot: None,
        flow_snapshot: None,
        greenbone_report: None,
        wazuh_report: None,
        napalm_snapshot: None,
        netmiko_snapshot: None,
        scrapli_snapshot: None,
        urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
        abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
        disable_circl: true,
    })
}

fn spec_to_beh_args(spec: platform::PipelineJobSpec) -> anyhow::Result<BehArgs> {
    Ok(BehArgs {
        workspace: PathBuf::from(spec.workspace_root),
        nazev: spec.nazev,
        scope: spec
            .scope
            .into_iter()
            .map(|item| item.parse::<IpNet>())
            .collect::<std::result::Result<Vec<_>, _>>()?,
        ports: spec.ports,
        profile: spec.profile,
        provider: spec.provider,
        supplement_vulners: spec.supplement_vulners,
        freeze: spec.freeze,
        production: false,
        nmap_xml: spec.nmap_xml.map(PathBuf::from),
        nmap_followup_xml: spec.nmap_followup_xml.map(PathBuf::from),
        suricata_eve: spec.suricata_eve.map(PathBuf::from),
        zeek_dir: spec.zeek_dir.map(PathBuf::from),
        porovnat_s: spec.porovnat_s,
        spustit_nmap: spec.spustit_nmap,
        hloubkove_overeni: false,
        web_fingerprint: spec.web_fingerprint,
        web_checks: spec.web_checks,
        pentest: spec.pentest,
        aggressive_pentest: spec.aggressive_pentest,
        httpx_bin: spec.httpx_bin.map(PathBuf::from),
        nuclei_bin: spec.nuclei_bin.map(PathBuf::from),
        nuclei_templates: spec.nuclei_templates.map(PathBuf::from),
        snmp_snapshot: spec.snmp_snapshot.map(PathBuf::from),
        librenms_snapshot: spec.librenms_snapshot.map(PathBuf::from),
        librenms_base_url: spec.librenms_base_url,
        librenms_token_env: spec.librenms_token_env,
        meraki_snapshot: spec.meraki_snapshot.map(PathBuf::from),
        meraki_network_id: spec.meraki_network_id,
        meraki_api_key_env: spec.meraki_api_key_env,
        meraki_timespan_seconds: spec.meraki_timespan_seconds,
        unifi_snapshot: spec.unifi_snapshot.map(PathBuf::from),
        unifi_devices_url: spec.unifi_devices_url,
        unifi_clients_url: spec.unifi_clients_url,
        unifi_links_url: spec.unifi_links_url,
        unifi_api_key_env: spec.unifi_api_key_env,
        aruba_snapshot: spec.aruba_snapshot.map(PathBuf::from),
        aruba_base_url: spec.aruba_base_url,
        aruba_token_env: spec.aruba_token_env,
        aruba_site_id: spec.aruba_site_id,
        omada_snapshot: spec.omada_snapshot.map(PathBuf::from),
        omada_devices_url: spec.omada_devices_url,
        omada_clients_url: spec.omada_clients_url,
        omada_links_url: spec.omada_links_url,
        omada_access_token_env: spec.omada_access_token_env,
        ntopng_snapshot: spec.ntopng_snapshot.map(PathBuf::from),
        flow_snapshot: spec.flow_snapshot.map(PathBuf::from),
        greenbone_report: spec.greenbone_report.map(PathBuf::from),
        wazuh_report: spec.wazuh_report.map(PathBuf::from),
        napalm_snapshot: spec.napalm_snapshot.map(PathBuf::from),
        netmiko_snapshot: spec.netmiko_snapshot.map(PathBuf::from),
        scrapli_snapshot: spec.scrapli_snapshot.map(PathBuf::from),
        urlhaus_auth_env: spec.urlhaus_auth_env,
        abuseipdb_key_env: spec.abuseipdb_key_env,
        disable_circl: spec.disable_circl,
    })
}

fn existing_file(path: PathBuf) -> Option<PathBuf> {
    path.is_file().then_some(path)
}

fn existing_dir(path: PathBuf) -> Option<PathBuf> {
    path.is_dir().then_some(path)
}
