use std::{
    convert::Infallible,
    fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tower_http::services::ServeDir;

use crate::{
    Result, ai, assistant, automation, config,
    model::{AppConfig, RunIndexEntry, RunReport},
    paths, platform, readiness,
    storage::Workspace,
    verification,
};

#[derive(Clone)]
struct AppState {
    workspace_root: Arc<PathBuf>,
    started_at: DateTime<Utc>,
    auth_required: bool,
    api_token: Arc<Option<String>>,
    platform_db: Arc<Option<PathBuf>>,
    automation_process: Arc<Mutex<Option<AutomationProcess>>>,
}

#[derive(Clone)]
struct AuthContext {
    subject: String,
}

struct AutomationProcess {
    child: Child,
    started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct AutomationRestartOptions {
    pentest: Option<String>,
}

pub async fn serve(addr: SocketAddr, workspace_root: PathBuf) -> Result<()> {
    let mut config = AppConfig::default();
    config.workspace_root = workspace_root.to_string_lossy().to_string();
    config.host = addr.ip().to_string();
    config.port = addr.port();
    serve_with_config(addr, config).await
}

pub async fn serve_with_config(addr: SocketAddr, config: AppConfig) -> Result<()> {
    let platform_db = platform::init_platform_from_config(&config)?;
    let state = AppState {
        workspace_root: Arc::new(PathBuf::from(&config.workspace_root)),
        started_at: Utc::now(),
        auth_required: config.security.require_api_token,
        api_token: Arc::new(config::resolve_api_token(&config)?),
        platform_db: Arc::new(platform_db),
        automation_process: Arc::new(Mutex::new(None)),
    };
    let ui_dir = paths::project_path(&["ui"]);

    let api = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/meta", get(meta))
        .route("/metrics", get(metrics))
        .route("/ai/status", get(get_ai_status))
        .route("/readiness", get(get_readiness))
        .route("/runs", get(list_runs))
        .route("/runs/{run_id}", get(get_run))
        .route("/runs/{run_id}/export/{format}", get(get_run_export))
        .route("/runs/{run_id}/assistant", post(post_run_assistant))
        .route(
            "/runs/{run_id}/assistant/stream",
            post(post_run_assistant_stream),
        )
        .route("/automation/latest", get(get_automation_latest))
        .route("/automation/status", get(get_automation_status))
        .route("/automation/restart", post(post_automation_restart))
        .route("/automation/reset", post(post_automation_reset))
        .route("/verification/latest", get(get_latest_verification))
        .route("/platform/cluster", get(get_platform_cluster))
        .route("/platform/jobs", get(get_platform_jobs))
        .route("/platform/users", get(get_platform_users))
        .route("/platform/ha", get(get_platform_ha))
        .with_state(state.clone());

    let app = Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(ui_dir))
        .layer(axum::middleware::map_response(disable_cache_headers))
        .with_state(state);

    println!("Bakula UI bezi na http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn disable_cache_headers(mut response: axum::response::Response) -> axum::response::Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert(header::EXPIRES, HeaderValue::from_static("0"));
    response
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "stav": "ok"
    }))
}

async fn ready(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let auth = authorize_for(&headers, &state, &["runs.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let runs = workspace.list_runs().map_err(to_http_error)?;
    let workspace_root = state.workspace_root.display().to_string();
    Ok::<_, (StatusCode, String)>(Json(serde_json::json!({
        "stav": "ready",
        "workspace": workspace_root,
        "runs_total": runs.len(),
        "started_at": state.started_at,
        "subject": auth.subject,
    })))
}

async fn meta(State(state): State<AppState>) -> impl IntoResponse {
    let workspace_root = state.workspace_root.display().to_string();
    Json(serde_json::json!({
        "service": "bakula-program",
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": state.started_at,
        "workspace_root": workspace_root,
        "auth_required": state.auth_required,
        "platform_enabled": state.platform_db.is_some(),
    }))
}

async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["metrics.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let runs = workspace.list_runs().map_err(to_http_error)?;
    let latest = runs.first();
    let metrics = render_metrics(&runs, latest);
    Ok::<_, (StatusCode, String)>((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics,
    ))
}

async fn get_ai_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    Ok::<_, (StatusCode, String)>(Json(ai::diagnose()))
}

async fn get_readiness(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let report = readiness::assess_workspace(&state.workspace_root, state.auth_required)
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(report))
}

async fn list_runs(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let runs = workspace.list_runs().map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(runs))
}

async fn get_run(
    Path(run_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let report = workspace.load_report(&run_id).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(report))
}

async fn get_run_export(
    Path((run_id, format)): Path<(String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let (filename, content_type) = match format.as_str() {
        "json" => ("report.json", "application/json; charset=utf-8"),
        "md" => ("report.md", "text/markdown; charset=utf-8"),
        "txt" => ("report.txt", "text/plain; charset=utf-8"),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Neznamy export format. Pouzij json, md nebo txt.".to_string(),
            ));
        }
    };
    let path = state
        .workspace_root
        .join("runs")
        .join(&run_id)
        .join(filename);
    let bytes = fs::read(&path).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).expect("static content type header is valid"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}-{}\"", run_id, filename))
            .expect("generated content disposition header is valid"),
    );
    Ok::<_, (StatusCode, String)>(response)
}

async fn post_run_assistant(
    Path(run_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<assistant::AssistantRequest>,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let response = assistant::answer_run_question(&state.workspace_root, &run_id, request)
        .await
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(response))
}

async fn post_run_assistant_stream(
    Path(run_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<assistant::AssistantRequest>,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let events = assistant::answer_run_question_events(
        state.workspace_root.as_ref().clone(),
        run_id,
        request,
    );
    let stream = ReceiverStream::new(events).map(|event| {
        let payload = serde_json::to_string(&event).unwrap_or_else(|error| {
            serde_json::json!({
                "type": "error",
                "error": error.to_string()
            })
            .to_string()
        });
        Ok::<Bytes, Infallible>(Bytes::from(format!("data: {payload}\n\n")))
    });
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    Ok::<_, (StatusCode, String)>(response)
}

async fn get_latest_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["verification.read"])?;
    Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let report = verification::load_latest_verification_report(&state.workspace_root)
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(report))
}

async fn get_automation_latest(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let path = automation::latest_report_path(&state.workspace_root);
    if !path.exists() {
        return Ok::<_, (StatusCode, String)>(Json(Option::<automation::AutomationReport>::None));
    }
    let bytes = fs::read(path).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let report =
        serde_json::from_slice::<automation::AutomationReport>(&bytes).map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Chyba serveru: {error}"),
            )
        })?;
    Ok::<_, (StatusCode, String)>(Json(Some(report)))
}

async fn get_automation_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let status = resolve_runtime_status(&state)
        .await
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(status))
}

async fn post_automation_restart(
    State(state): State<AppState>,
    Query(options): Query<AutomationRestartOptions>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["jobs.write"])?;
    let mut guard = state.automation_process.lock().await;
    if let Some(process) = guard.as_mut() {
        match process.child.try_wait() {
            Ok(None) => {
                return Err((
                    StatusCode::CONFLICT,
                    "Autopilot už běží. Použij reset nebo počkej na dokončení.".to_string(),
                ));
            }
            Ok(Some(_)) => {
                *guard = None;
            }
            Err(error) => {
                *guard = None;
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Chyba serveru: {error}"),
                ));
            }
        }
    }

    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let latest_run_id = workspace
        .list_runs()
        .map_err(to_http_error)?
        .first()
        .map(|item| item.run_id.clone())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Ve workspace není žádný běh, ze kterého by šlo odvodit restart.".to_string(),
        ))?;
    let latest_report = workspace
        .load_report(&latest_run_id)
        .map_err(to_http_error)?;
    let mut command =
        build_restart_command(&state.workspace_root, &latest_report).map_err(to_http_error)?;
    apply_restart_pentest_options(&mut command, &options);
    automation::begin_runtime(&state.workspace_root, 1, &latest_report.run.nazev)
        .map_err(to_http_error)?;
    let exe = std::env::current_exe().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let mut child = Command::new(exe);
    child.args(&command);
    child.stdout(Stdio::null());
    child.stderr(Stdio::null());
    let child = child.spawn().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let pid = child.id();
    *guard = Some(AutomationProcess {
        child,
        started_at: Utc::now(),
    });
    Ok::<_, (StatusCode, String)>(Json(serde_json::json!({
        "state": "starting",
        "pid": pid,
        "command": command,
    })))
}

async fn post_automation_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["jobs.write"])?;
    let mut guard = state.automation_process.lock().await;
    if let Some(process) = guard.as_mut() {
        let _ = process.child.kill();
    }
    *guard = None;
    let status = automation::clear_runtime_status(&state.workspace_root).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(serde_json::json!({
        "state": "reset",
        "status_path": status.display().to_string(),
    })))
}

async fn get_platform_cluster(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["cluster.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let snapshot = platform::snapshot(db).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(snapshot))
}

async fn get_platform_jobs(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["jobs.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let jobs = platform::list_jobs(db).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(jobs))
}

async fn get_platform_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["users.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let users = platform::list_users(db).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(users))
}

async fn get_platform_ha(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["cluster.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let status = platform::ha_status(db, None).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(status))
}

fn authorize_for(
    headers: &HeaderMap,
    state: &AppState,
    required_permissions: &[&str],
) -> std::result::Result<AuthContext, (StatusCode, String)> {
    let provided = bearer_token(headers).or_else(|| api_key_header(headers));
    let read_only_request = is_read_only_permissions(required_permissions);
    if let Some(db_path) = state.platform_db.as_deref() {
        let token = provided.ok_or((
            StatusCode::UNAUTHORIZED,
            "Pro pristup k API je vyzadovan platformni token.".to_string(),
        ))?;
        let identity = platform::authenticate_token(db_path, &token).map_err(to_http_error)?;
        if let Some(identity) = identity {
            ensure_permissions(&identity, required_permissions)?;
            return Ok(AuthContext {
                subject: identity.username,
            });
        }
        if let Some(expected) = state.api_token.as_deref() {
            if token == expected {
                return Ok(admin_context("static-admin"));
            }
        }
        return Err((
            StatusCode::UNAUTHORIZED,
            "Chybi nebo je neplatny platformni token.".to_string(),
        ));
    }

    if !state.auth_required {
        return Ok(admin_context("anonymous-admin"));
    }
    if read_only_request {
        return Ok(admin_context("anonymous-readonly"));
    }
    let Some(expected) = state.api_token.as_deref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server neni nakonfigurovan pro overeni API tokenu.".to_string(),
        ));
    };
    match provided {
        Some(token) if token == expected => Ok(admin_context("static-admin")),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "Chybi nebo je neplatny API token.".to_string(),
        )),
    }
}

fn is_read_only_permissions(required_permissions: &[&str]) -> bool {
    !required_permissions.is_empty()
        && required_permissions
            .iter()
            .all(|permission| permission.ends_with(".read") || *permission == "metrics.read")
}

fn ensure_permissions(
    auth: &platform::AuthIdentity,
    required_permissions: &[&str],
) -> std::result::Result<(), (StatusCode, String)> {
    if required_permissions.is_empty() || auth.permissions.iter().any(|item| item == "*") {
        return Ok(());
    }
    let missing = required_permissions
        .iter()
        .copied()
        .filter(|permission| !auth.permissions.iter().any(|item| item == permission))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            format!("Chybi opravneni: {}.", missing.join(", ")),
        ))
    }
}

fn admin_context(subject: &str) -> AuthContext {
    AuthContext {
        subject: subject.to_string(),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_string())
}

fn api_key_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn render_metrics(runs: &[RunIndexEntry], latest: Option<&RunIndexEntry>) -> String {
    let hosts_total: usize = runs.iter().map(|item| item.hosts_total).sum();
    let services_total: usize = runs.iter().map(|item| item.services_total).sum();
    let cves_total: usize = runs.iter().map(|item| item.cves_total).sum();
    let events_total: usize = runs.iter().map(|item| item.events_total).sum();
    let findings_total: usize = runs.iter().map(|item| item.findings_total).sum();
    let triage_total: usize = runs.iter().map(|item| item.triage_actions_total).sum();
    let lanes_total: usize = runs.iter().map(|item| item.monitoring_lanes_total).sum();
    format!(
        concat!(
            "# HELP bakula_runs_total Pocet ulozenych behu.\n",
            "# TYPE bakula_runs_total gauge\n",
            "bakula_runs_total {}\n",
            "# HELP bakula_hosts_total_sum Soucet hostu napric ulozenymi behy.\n",
            "# TYPE bakula_hosts_total_sum gauge\n",
            "bakula_hosts_total_sum {}\n",
            "# HELP bakula_services_total_sum Soucet sluzeb napric ulozenymi behy.\n",
            "# TYPE bakula_services_total_sum gauge\n",
            "bakula_services_total_sum {}\n",
            "# HELP bakula_cves_total_sum Soucet CVE napric ulozenymi behy.\n",
            "# TYPE bakula_cves_total_sum gauge\n",
            "bakula_cves_total_sum {}\n",
            "# HELP bakula_events_total_sum Soucet udalosti napric ulozenymi behy.\n",
            "# TYPE bakula_events_total_sum gauge\n",
            "bakula_events_total_sum {}\n",
            "# HELP bakula_findings_total_sum Soucet nalezu napric ulozenymi behy.\n",
            "# TYPE bakula_findings_total_sum gauge\n",
            "bakula_findings_total_sum {}\n",
            "# HELP bakula_triage_actions_total_sum Soucet triage kroku napric ulozenymi behy.\n",
            "# TYPE bakula_triage_actions_total_sum gauge\n",
            "bakula_triage_actions_total_sum {}\n",
            "# HELP bakula_monitoring_lanes_total_sum Soucet monitoring lanes napric ulozenymi behy.\n",
            "# TYPE bakula_monitoring_lanes_total_sum gauge\n",
            "bakula_monitoring_lanes_total_sum {}\n",
            "# HELP bakula_latest_hosts_total Hoste v poslednim behu.\n",
            "# TYPE bakula_latest_hosts_total gauge\n",
            "bakula_latest_hosts_total {}\n",
            "# HELP bakula_latest_findings_total Nalezy v poslednim behu.\n",
            "# TYPE bakula_latest_findings_total gauge\n",
            "bakula_latest_findings_total {}\n",
        ),
        runs.len(),
        hosts_total,
        services_total,
        cves_total,
        events_total,
        findings_total,
        triage_total,
        lanes_total,
        latest.map(|item| item.hosts_total).unwrap_or_default(),
        latest.map(|item| item.findings_total).unwrap_or_default(),
    )
}

fn to_http_error(error: crate::BakulaError) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Chyba serveru: {error}"),
    )
}

async fn resolve_runtime_status(
    state: &AppState,
) -> crate::Result<automation::RuntimeAutomationStatus> {
    let mut running = false;
    {
        let mut guard = state.automation_process.lock().await;
        if let Some(process) = guard.as_mut() {
            match process.child.try_wait() {
                Ok(None) => {
                    running = true;
                }
                Ok(Some(exit)) => {
                    if !exit.success() {
                        let message = format!(
                            "Autopilot ukončen s chybou. Start: {}.",
                            process.started_at.to_rfc3339()
                        );
                        let _ = automation::fail_runtime(&state.workspace_root, &message);
                    }
                    *guard = None;
                }
                Err(error) => {
                    let _ = automation::fail_runtime(
                        &state.workspace_root,
                        &format!("Nelze ověřit stav autopilota: {error}"),
                    );
                    *guard = None;
                }
            }
        }
    }
    let mut status = automation::load_runtime_status(&state.workspace_root)?;
    status.process_running = running;
    Ok(status)
}

fn build_restart_command(
    workspace_root: &FsPath,
    report: &RunReport,
) -> crate::Result<Vec<String>> {
    let mut command = vec![
        "autopilot".to_string(),
        "spust".to_string(),
        "--workspace".to_string(),
        workspace_root.display().to_string(),
        "--nazev".to_string(),
        base_run_name(&report.run.nazev),
        "--scope".to_string(),
        report
            .run
            .scope
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>()
            .join(","),
        "--ports".to_string(),
        report
            .run
            .ports
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>()
            .join(","),
        "--profile".to_string(),
        report.run.profile.clone(),
        "--provider".to_string(),
        report.run.provider.clone(),
        "--cycles".to_string(),
        "1".to_string(),
    ];

    if report.run.enrichment_mode == "freeze" {
        command.push("--freeze".to_string());
    }
    if report.run.sources.nmap_mode.as_deref() == Some("live") {
        command.push("--spustit-nmap".to_string());
    } else if let Some(path) = existing_string_path(report.run.sources.nmap_xml.as_deref()) {
        command.push("--nmap-xml".to_string());
        command.push(path);
    } else {
        command.push("--spustit-nmap".to_string());
    }

    push_existing_path_arg(
        &mut command,
        "--suricata-eve",
        report.run.sources.suricata_eve.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--zeek-dir",
        report.run.sources.zeek_dir.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--snmp-snapshot",
        report.run.sources.snmp_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--librenms-snapshot",
        report.run.sources.librenms_snapshot.as_deref(),
    );
    if let Some(url) = report.run.sources.librenms_base_url.as_deref() {
        command.push("--librenms-base-url".to_string());
        command.push(url.to_string());
    }
    push_existing_path_arg(
        &mut command,
        "--meraki-snapshot",
        report.run.sources.meraki_snapshot.as_deref(),
    );
    if let Some(value) = report.run.sources.meraki_network_id.as_deref() {
        command.push("--meraki-network-id".to_string());
        command.push(value.to_string());
    }
    push_existing_path_arg(
        &mut command,
        "--unifi-snapshot",
        report.run.sources.unifi_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--aruba-snapshot",
        report.run.sources.aruba_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--omada-snapshot",
        report.run.sources.omada_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--ntopng-snapshot",
        report.run.sources.ntopng_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--flow-snapshot",
        report.run.sources.flow_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--greenbone-report",
        report.run.sources.greenbone_report.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--wazuh-report",
        report.run.sources.wazuh_report.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--napalm-snapshot",
        report.run.sources.napalm_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--netmiko-snapshot",
        report.run.sources.netmiko_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--scrapli-snapshot",
        report.run.sources.scrapli_snapshot.as_deref(),
    );

    let web_lane_sources = report
        .monitoring_lanes
        .iter()
        .map(|lane| lane.source.as_str())
        .collect::<Vec<_>>();
    if report.summary.web_probes_total > 0 || web_lane_sources.contains(&"httpx") {
        command.push("--web-fingerprint".to_string());
    }
    if report.summary.active_checks_total > 0 || web_lane_sources.contains(&"nuclei") {
        command.push("--web-checks".to_string());
    }
    if web_lane_sources.contains(&"internal-pentest") {
        command.push("--pentest".to_string());
        if report
            .monitoring_lanes
            .iter()
            .find(|lane| lane.source == "internal-pentest")
            .is_some_and(|lane| lane.evidence.iter().any(|item| item == "mode=aggressive"))
        {
            command.push("--aggressive-pentest".to_string());
        }
    }

    let httpx = paths::project_path(&["tools", "projectdiscovery", "httpx", "httpx.exe"]);
    if httpx.exists() {
        command.push("--httpx-bin".to_string());
        command.push(httpx.display().to_string());
    }
    let nuclei = paths::project_path(&["tools", "projectdiscovery", "nuclei", "nuclei.exe"]);
    if nuclei.exists() {
        command.push("--nuclei-bin".to_string());
        command.push(nuclei.display().to_string());
    }
    let nuclei_templates = paths::project_path(&["resources", "nuclei-templates", "controlled"]);
    if nuclei_templates.exists() {
        command.push("--nuclei-templates".to_string());
        command.push(nuclei_templates.display().to_string());
    }

    Ok(command)
}

fn apply_restart_pentest_options(command: &mut Vec<String>, options: &AutomationRestartOptions) {
    let Some(mode) = options.pentest.as_deref() else {
        return;
    };
    match mode.trim().to_ascii_lowercase().as_str() {
        "smart" | "safe" | "on" | "true" => {
            push_flag_once(command, "--pentest");
        }
        "aggressive" | "hard" => {
            push_flag_once(command, "--pentest");
            push_flag_once(command, "--aggressive-pentest");
        }
        _ => {}
    }
}

fn push_flag_once(command: &mut Vec<String>, flag: &str) {
    if !command.iter().any(|item| item == flag) {
        command.push(flag.to_string());
    }
}

fn push_existing_path_arg(command: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(path) = existing_string_path(value) {
        command.push(flag.to_string());
        command.push(path);
    }
}

fn existing_string_path(value: Option<&str>) -> Option<String> {
    let path = PathBuf::from(value?);
    path.exists().then(|| path.display().to_string())
}

fn base_run_name(value: &str) -> String {
    value
        .rsplit_once(" / cyklus ")
        .map(|(base, _)| base.to_string())
        .unwrap_or_else(|| value.to_string())
}
