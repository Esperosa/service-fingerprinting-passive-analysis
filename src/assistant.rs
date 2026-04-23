use std::{
    cmp::Reverse,
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::{
    BakulaError, Result, ai, intel,
    model::{
        CveRecord, Finding, HostReport, MonitoringLane, NetworkAsset, RunReport, ServiceReport,
        Severity, TriageAction,
    },
    storage::Workspace,
    vuln,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AssistantTurn {
    pub role: String,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssistantRequest {
    pub prompt: String,
    #[serde(default)]
    pub detail_panel: Option<String>,
    #[serde(default)]
    pub selected_node_id: Option<String>,
    #[serde(default)]
    pub selected_finding_id: Option<String>,
    #[serde(default)]
    pub selected_asset_id: Option<String>,
    #[serde(default)]
    pub selected_action_id: Option<String>,
    #[serde(default)]
    pub history: Vec<AssistantTurn>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssistantSource {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssistantResponse {
    pub answer: String,
    pub mode: String,
    pub context_title: String,
    #[serde(default)]
    pub sources: Vec<AssistantSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssistantStreamEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct AssistantContext {
    run_name: String,
    scope: String,
    summary_line: String,
    selected_host: Option<HostSummary>,
    selected_service: Option<ServiceSummary>,
    selected_asset: Option<AssetSummary>,
    selected_finding: Option<FindingSummary>,
    selected_action: Option<ActionSummary>,
    top_findings: Vec<FindingSummary>,
    decision_lanes: Vec<DecisionLaneSummary>,
    sources: Vec<AssistantSource>,
}

#[derive(Debug, Clone)]
struct HostSummary {
    name: String,
    ip: String,
    hostname: Option<String>,
    services: Vec<ServiceSummary>,
}

#[derive(Debug, Clone)]
struct ServiceSummary {
    label: String,
    product: Option<String>,
    version: Option<String>,
    cpe: Vec<String>,
    cves: Vec<CveRecord>,
    priorita: String,
}

#[derive(Debug, Clone)]
struct AssetSummary {
    asset_id: String,
    name: String,
    asset_type: String,
    source: String,
    ip: Option<String>,
    vendor: Option<String>,
    model: Option<String>,
    linked_host_key: Option<String>,
}

#[derive(Debug, Clone)]
struct FindingSummary {
    finding_id: String,
    title: String,
    rationale: String,
    recommendation: String,
    severity: String,
    host_key: Option<String>,
    service_key: Option<String>,
    evidence: Vec<String>,
}

#[derive(Debug, Clone)]
struct ActionSummary {
    action_id: String,
    title: String,
    rationale: String,
    priority: String,
    recommended_tools: Vec<String>,
    evidence: Vec<String>,
}

#[derive(Debug, Clone)]
struct DecisionLaneSummary {
    source: String,
    title: String,
    status: String,
    summary: String,
    evidence: Vec<String>,
    recommended_tools: Vec<String>,
}

#[derive(Debug, Clone)]
enum LlmProvider {
    OpenAiResponses,
    OpenAiCompatible,
    Ollama,
}

#[derive(Debug, Clone)]
struct LlmConfig {
    provider: LlmProvider,
    model: String,
    base_url: String,
    api_key: Option<String>,
}

impl LlmConfig {
    fn mode_name(&self) -> &'static str {
        match self.provider {
            LlmProvider::OpenAiResponses => "openai",
            LlmProvider::OpenAiCompatible => "openai-compatible",
            LlmProvider::Ollama => "ollama",
        }
    }

    fn mode_label(&self) -> String {
        format!("{}:{}", self.mode_name(), self.model)
    }
}

pub async fn answer_run_question(
    workspace_root: &Path,
    run_id: &str,
    request: AssistantRequest,
) -> Result<AssistantResponse> {
    let workspace = Workspace::open(workspace_root)?;
    let report = workspace.load_report(run_id)?;
    let mut context = build_context(&report, &request);
    let extra_sources =
        fetch_vulners_sources(workspace_root, context.selected_service.as_ref()).await?;
    merge_sources(&mut context.sources, extra_sources);

    let answer = if should_force_grounded_answer(&request.prompt) {
        AssistantResponse {
            answer: deterministic_answer(&context, &request.prompt),
            mode: "grounded-local".to_string(),
            context_title: context_title(&context),
            sources: context.sources.clone(),
        }
    } else if let Some(llm) = llm_config_from_env() {
        match answer_with_llm(&llm, &context, &request).await {
            Ok(text) if !text.trim().is_empty() => AssistantResponse {
                answer: finalize_model_answer(&text, &context, &request.prompt),
                mode: llm.mode_label(),
                context_title: context_title(&context),
                sources: context.sources.clone(),
            },
            Ok(_) | Err(_) => AssistantResponse {
                answer: deterministic_answer(&context, &request.prompt),
                mode: "deterministic-fallback".to_string(),
                context_title: context_title(&context),
                sources: context.sources.clone(),
            },
        }
    } else {
        AssistantResponse {
            answer: deterministic_answer(&context, &request.prompt),
            mode: "deterministic".to_string(),
            context_title: context_title(&context),
            sources: context.sources.clone(),
        }
    };

    Ok(answer)
}

pub fn answer_run_question_events(
    workspace_root: PathBuf,
    run_id: String,
    request: AssistantRequest,
) -> mpsc::Receiver<AssistantStreamEvent> {
    let (tx, rx) = mpsc::channel(48);
    tokio::spawn(async move {
        if let Err(error) =
            answer_run_question_stream_inner(&workspace_root, &run_id, request, tx.clone()).await
        {
            let _ = tx
                .send(AssistantStreamEvent {
                    event_type: "error".to_string(),
                    text: None,
                    mode: None,
                    sources: Vec::new(),
                    error: Some(error.to_string()),
                })
                .await;
        }
    });
    rx
}

async fn answer_run_question_stream_inner(
    workspace_root: &Path,
    run_id: &str,
    request: AssistantRequest,
    tx: mpsc::Sender<AssistantStreamEvent>,
) -> Result<()> {
    let workspace = Workspace::open(workspace_root)?;
    let report = workspace.load_report(run_id)?;
    let mut context = build_context(&report, &request);
    let extra_sources =
        fetch_vulners_sources(workspace_root, context.selected_service.as_ref()).await?;
    merge_sources(&mut context.sources, extra_sources);

    let mut mode = "deterministic".to_string();
    let answer: String;
    if should_force_grounded_answer(&request.prompt) {
        mode = "grounded-local".to_string();
        answer = deterministic_answer(&context, &request.prompt);
        emit_text_chunks(&tx, &answer).await;
    } else if let Some(llm) = llm_config_from_env() {
        mode = llm.mode_label();
        let result = match llm.provider {
            LlmProvider::Ollama => answer_with_ollama_stream(&llm, &context, &request, &tx).await,
            _ => answer_with_llm(&llm, &context, &request).await,
        };
        match result {
            Ok(text) if !text.trim().is_empty() => {
                answer = finalize_model_answer(&text, &context, &request.prompt);
                if !matches!(llm.provider, LlmProvider::Ollama) {
                    emit_text_chunks(&tx, &answer).await;
                }
            }
            Ok(_) | Err(_) => {
                mode = "deterministic-fallback".to_string();
                answer = deterministic_answer(&context, &request.prompt);
                emit_text_chunks(&tx, &answer).await;
            }
        }
    } else {
        answer = deterministic_answer(&context, &request.prompt);
        emit_text_chunks(&tx, &answer).await;
    }

    tx.send(AssistantStreamEvent {
        event_type: "done".to_string(),
        text: None,
        mode: Some(mode),
        sources: context
            .sources
            .iter()
            .map(|source| source.label.clone())
            .collect(),
        error: None,
    })
    .await
    .ok();
    Ok(())
}

fn should_force_grounded_answer(prompt: &str) -> bool {
    let normalized = prompt.to_lowercase();
    normalized.contains("jak to oprav")
        || normalized.contains("jak oprav")
        || normalized.contains("jak vyřeš")
        || normalized.contains("jak vyres")
        || normalized.contains("co s tím")
        || normalized.contains("co s tim")
        || normalized.contains("co mám dělat")
        || normalized.contains("co mam delat")
        || normalized.contains("co mám udělat")
        || normalized.contains("co mam udelat")
        || normalized.contains("co mám řešit")
        || normalized.contains("co mam resit")
        || normalized.contains("porad")
        || normalized.contains("pomoz")
        || normalized.contains("další krok")
        || normalized.contains("dalsi krok")
}

fn finalize_model_answer(text: &str, context: &AssistantContext, prompt: &str) -> String {
    let cleaned = clean_model_answer(text).trim().to_string();
    if !should_force_grounded_answer(prompt) {
        return cleaned;
    }
    let target = context
        .selected_finding
        .as_ref()
        .map(finding_target)
        .or_else(|| context.selected_host.as_ref().map(|host| host.ip.clone()))
        .or_else(|| {
            context
                .selected_asset
                .as_ref()
                .and_then(|asset| asset.ip.clone())
        })
        .unwrap_or_default();
    let lower = cleaned.to_lowercase();
    if cleaned.is_empty()
        || (!target.is_empty() && !cleaned.contains(&target))
        || (!lower.contains("ověř") && !lower.contains("spusť") && !lower.contains("zkontroluj"))
    {
        deterministic_answer(context, prompt)
    } else {
        cleaned
    }
}

fn llm_config_from_env() -> Option<LlmConfig> {
    llm_config_from_lookup(|key| env::var(key).ok())
}

fn llm_config_from_lookup<F>(mut lookup: F) -> Option<LlmConfig>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut env_text = |key: &str| {
        lookup(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let requested = env_text("BAKULA_LLM_PROVIDER")
        .unwrap_or_else(|| "auto".to_string())
        .trim()
        .to_ascii_lowercase();
    if matches!(
        requested.as_str(),
        "off" | "none" | "disabled" | "deterministic"
    ) {
        return None;
    }

    if requested == "openai" || requested == "openai-responses" {
        return env_text("OPENAI_API_KEY").map(|api_key| LlmConfig {
            provider: LlmProvider::OpenAiResponses,
            model: env_text("OPENAI_ASSISTANT_MODEL").unwrap_or_else(|| "gpt-5.2-mini".to_string()),
            base_url: env_text("OPENAI_BASE_URL")
                .unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
            api_key: Some(api_key),
        });
    }

    if requested == "openai-compatible"
        || requested == "local-openai"
        || env_text("OPENAI_COMPATIBLE_BASE_URL").is_some()
        || env_text("BAKULA_LLM_BASE_URL").is_some()
    {
        return Some(LlmConfig {
            provider: LlmProvider::OpenAiCompatible,
            model: env_text("OPENAI_COMPATIBLE_MODEL")
                .or_else(|| env_text("BAKULA_LOCAL_LLM_MODEL"))
                .or_else(|| env_text("BAKULA_LLM_MODEL"))
                .or_else(|| env_text("OPENAI_ASSISTANT_MODEL"))
                .unwrap_or_else(|| "Qwen/Qwen3-8B".to_string()),
            base_url: env_text("OPENAI_COMPATIBLE_BASE_URL")
                .or_else(|| env_text("BAKULA_LLM_BASE_URL"))
                .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string()),
            api_key: env_text("OPENAI_COMPATIBLE_API_KEY")
                .or_else(|| env_text("BAKULA_LLM_API_KEY")),
        });
    }

    Some(LlmConfig {
        provider: LlmProvider::Ollama,
        model: env_text("OLLAMA_ASSISTANT_MODEL")
            .or_else(|| env_text("BAKULA_LOCAL_LLM_MODEL"))
            .or_else(|| env_text("OLLAMA_MODEL"))
            .or_else(|| env_text("BAKULA_LLM_MODEL"))
            .unwrap_or_else(|| ai::SKOKY_MODEL.to_string()),
        base_url: env_text("OLLAMA_BASE_URL")
            .unwrap_or_else(|| "http://127.0.0.1:11434".to_string()),
        api_key: None,
    })
}

fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn build_context(report: &RunReport, request: &AssistantRequest) -> AssistantContext {
    let host_candidates = report.hosts.iter().map(host_summary).collect::<Vec<_>>();
    let asset_candidates = report
        .network_assets
        .iter()
        .map(asset_summary)
        .collect::<Vec<_>>();
    let finding_candidates = report
        .findings
        .iter()
        .map(finding_summary)
        .collect::<Vec<_>>();
    let action_candidates = report
        .triage_actions
        .iter()
        .map(action_summary)
        .collect::<Vec<_>>();

    let selected_host = request
        .selected_node_id
        .as_deref()
        .and_then(|needle| {
            host_candidates.iter().find(|host| {
                host.ip == needle
                    || host.name == needle
                    || host.hostname.as_deref() == Some(needle)
                    || report
                        .hosts
                        .iter()
                        .any(|raw| raw.host_key == needle && raw.ip == host.ip)
            })
        })
        .cloned();

    let selected_asset = request
        .selected_asset_id
        .as_deref()
        .or(request.selected_node_id.as_deref())
        .and_then(|needle| {
            asset_candidates.iter().find(|asset| {
                asset.asset_id == needle
                    || asset.ip.as_deref() == Some(needle)
                    || asset.linked_host_key.as_deref() == Some(needle)
            })
        })
        .cloned();

    let selected_finding = request
        .selected_finding_id
        .as_deref()
        .and_then(|needle| {
            finding_candidates
                .iter()
                .find(|finding| finding.finding_id == needle)
        })
        .cloned()
        .or_else(|| {
            request.selected_node_id.as_deref().and_then(|needle| {
                top_findings(&finding_candidates)
                    .into_iter()
                    .find(|finding| {
                        finding.host_key.as_deref() == Some(needle)
                            || finding.service_key.as_deref() == Some(needle)
                    })
            })
        });

    let selected_action = request
        .selected_action_id
        .as_deref()
        .and_then(|needle| {
            action_candidates
                .iter()
                .find(|action| action.action_id == needle)
        })
        .cloned();

    let selected_service = selected_finding
        .as_ref()
        .and_then(|finding| {
            finding
                .service_key
                .as_deref()
                .and_then(|needle| find_service(report, needle).map(service_summary))
        })
        .or_else(|| {
            selected_host.as_ref().and_then(|host| {
                host.services
                    .iter()
                    .max_by_key(|service| severity_rank(&service.priorita))
                    .cloned()
            })
        })
        .or_else(|| {
            selected_asset
                .as_ref()
                .and_then(|asset| asset.linked_host_key.as_deref())
                .and_then(|needle| find_host(report, needle))
                .and_then(|host| {
                    host.services
                        .iter()
                        .max_by_key(|service| severity_rank(&service.priorita))
                        .map(service_summary)
                })
        });

    let mut sources = build_sources(report, selected_service.as_ref(), selected_finding.as_ref());
    if sources.is_empty() {
        sources.extend(
            report
                .intel_matches
                .iter()
                .flat_map(|item| item.references.iter().cloned())
                .take(3)
                .map(|url| AssistantSource {
                    label: short_source_label(&url),
                    url: Some(url),
                }),
        );
    }

    AssistantContext {
        run_name: report.run.nazev.clone(),
        scope: report
            .run
            .scope
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        summary_line: format!(
            "{} hosté, {} služby, {} rizik, {} kroků.",
            report.summary.hosts_total,
            report.summary.services_total,
            report.summary.findings_total,
            report.summary.triage_actions_total
        ),
        selected_host,
        selected_service,
        selected_asset,
        selected_finding,
        selected_action,
        top_findings: top_findings(&finding_candidates),
        decision_lanes: decision_lane_summaries(report),
        sources,
    }
}

fn host_summary(host: &HostReport) -> HostSummary {
    HostSummary {
        name: host.hostname.clone().unwrap_or_else(|| host.ip.clone()),
        ip: host.ip.clone(),
        hostname: host.hostname.clone(),
        services: host.services.iter().map(service_summary).collect(),
    }
}

fn service_summary(service: &ServiceReport) -> ServiceSummary {
    ServiceSummary {
        label: format!("{}/{}", service.inventory.service_name, service.port),
        product: service.inventory.product.clone(),
        version: service.inventory.version.clone(),
        cpe: service
            .cpe
            .iter()
            .map(|item| item.cpe23_uri.clone())
            .collect(),
        cves: service.cves.clone(),
        priorita: service.priorita.clone(),
    }
}

fn asset_summary(asset: &NetworkAsset) -> AssetSummary {
    AssetSummary {
        asset_id: asset.asset_id.clone(),
        name: asset.name.clone(),
        asset_type: asset.asset_type.clone(),
        source: asset.source.clone(),
        ip: asset.ip.clone(),
        vendor: asset.vendor.clone(),
        model: asset.model.clone(),
        linked_host_key: asset.linked_host_key.clone(),
    }
}

fn finding_summary(finding: &Finding) -> FindingSummary {
    FindingSummary {
        finding_id: finding.finding_id.clone(),
        title: finding.title.clone(),
        rationale: finding.rationale.clone(),
        recommendation: finding.recommendation.clone(),
        severity: severity_text(finding.severity),
        host_key: finding.host_key.clone(),
        service_key: finding.service_key.clone(),
        evidence: finding.evidence.iter().take(8).cloned().collect(),
    }
}

fn action_summary(action: &TriageAction) -> ActionSummary {
    ActionSummary {
        action_id: action.action_id.clone(),
        title: action.title.clone(),
        rationale: action.rationale.clone(),
        priority: severity_text(action.priority),
        recommended_tools: action.recommended_tools.clone(),
        evidence: action.evidence.iter().take(8).cloned().collect(),
    }
}

fn decision_lane_summaries(report: &RunReport) -> Vec<DecisionLaneSummary> {
    let mut lanes = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "automation")
        .filter(|lane| {
            lane.source.contains("decision")
                || lane.source.contains("validation")
                || lane.source.contains("pentest")
                || lane.source.starts_with("agent")
                || lane.source.starts_with("mas")
                || matches!(
                    lane.source.as_str(),
                    "case-memory"
                        | "ai-context-bridge"
                        | "planner"
                        | "followup"
                        | "forensic"
                        | "live-observer"
                        | "correlator"
                        | "intel"
                )
        })
        .map(decision_lane_summary)
        .collect::<Vec<_>>();
    lanes.sort_by_key(|lane| decision_lane_rank(&lane.source));
    lanes.into_iter().take(18).collect()
}

fn decision_lane_summary(lane: &MonitoringLane) -> DecisionLaneSummary {
    DecisionLaneSummary {
        source: lane.source.clone(),
        title: lane.title.clone(),
        status: lane.status.clone(),
        summary: lane.summary.clone(),
        evidence: lane.evidence.iter().take(8).cloned().collect(),
        recommended_tools: lane.recommended_tools.clone(),
    }
}

fn decision_lane_rank(source: &str) -> usize {
    if source.contains("risk") || source.contains("hypoth") || source.contains("inference") {
        0
    } else if source.contains("governor") || source.contains("lifecycle") {
        1
    } else if source == "mas-consensus" {
        2
    } else if source.contains("validation")
        || source.contains("pentest")
        || source == "ai-context-bridge"
    {
        3
    } else if source == "case-memory" {
        4
    } else if source.starts_with("agent") {
        5
    } else {
        6
    }
}

fn top_findings(findings: &[FindingSummary]) -> Vec<FindingSummary> {
    let mut items = findings.to_vec();
    items.sort_by_key(|item| Reverse(severity_rank(&item.severity)));
    items.into_iter().take(3).collect()
}

fn build_sources(
    report: &RunReport,
    selected_service: Option<&ServiceSummary>,
    selected_finding: Option<&FindingSummary>,
) -> Vec<AssistantSource> {
    let mut sources = Vec::new();
    if let Some(service) = selected_service {
        for cve in service.cves.iter().take(4) {
            push_source(
                &mut sources,
                AssistantSource {
                    label: cve.cve_id.clone(),
                    url: cve.references.first().cloned(),
                },
            );
        }
    }
    if let Some(finding) = selected_finding {
        if let Some(host_key) = &finding.host_key {
            for intel in report
                .intel_matches
                .iter()
                .filter(|item| item.linked_host_key.as_deref() == Some(host_key))
                .take(2)
            {
                for reference in &intel.references {
                    push_source(
                        &mut sources,
                        AssistantSource {
                            label: format!("{} · {}", intel.source, intel.indicator),
                            url: Some(reference.clone()),
                        },
                    );
                }
            }
        }
    }
    sources
}

async fn fetch_vulners_sources(
    workspace_root: &Path,
    selected_service: Option<&ServiceSummary>,
) -> Result<Vec<AssistantSource>> {
    if env::var("VULNERS_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        return Ok(Vec::new());
    }
    let Some(cpe) = selected_service.and_then(|service| service.cpe.first().cloned()) else {
        return Ok(Vec::new());
    };
    let cache_dir = workspace_root.join("cache");
    tokio::task::spawn_blocking(move || {
        let provider = vuln::build_provider(&cache_dir, "vulners", false, false)?;
        let records = provider.query_by_cpe(&cpe)?;
        Ok::<_, BakulaError>(
            records
                .into_iter()
                .take(3)
                .map(|record| AssistantSource {
                    label: format!("Vulners · {}", record.cve_id),
                    url: record.references.first().cloned(),
                })
                .collect::<Vec<_>>(),
        )
    })
    .await
    .map_err(|error| BakulaError::Processing(format!("Vulners helpdesk task selhal: {error}")))?
}

async fn answer_with_llm(
    config: &LlmConfig,
    context: &AssistantContext,
    request: &AssistantRequest,
) -> Result<String> {
    let answer = match config.provider {
        LlmProvider::OpenAiResponses => {
            answer_with_openai_responses(config, context, request).await
        }
        LlmProvider::OpenAiCompatible => {
            answer_with_chat_completions(config, context, request).await
        }
        LlmProvider::Ollama => answer_with_ollama(config, context, request).await,
    }?;
    Ok(clean_model_answer(&answer))
}

async fn answer_with_openai_responses(
    config: &LlmConfig,
    context: &AssistantContext,
    request: &AssistantRequest,
) -> Result<String> {
    let api_key = config.api_key.as_deref().ok_or_else(|| {
        BakulaError::Config("Chybí OPENAI_API_KEY pro helpdesk model.".to_string())
    })?;
    let client = reqwest::Client::builder()
        .user_agent("bakula-program/0.1")
        .timeout(llm_timeout(25))
        .build()?;

    let payload = serde_json::json!({
        "model": config.model,
        "instructions": assistant_system_prompt(),
        "input": build_openai_input(context, request),
    });
    let response: serde_json::Value = client
        .post(format!(
            "{}/responses",
            config.base_url.trim_end_matches('/')
        ))
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    extract_openai_text(&response).ok_or_else(|| {
        BakulaError::Processing("OpenAI helpdesk nevrátil textovou odpověď.".to_string())
    })
}

async fn answer_with_chat_completions(
    config: &LlmConfig,
    context: &AssistantContext,
    request: &AssistantRequest,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("bakula-program/0.1")
        .timeout(llm_timeout(25))
        .build()?;
    let payload = serde_json::json!({
        "model": config.model,
        "temperature": 0.2,
        "messages": [
            { "role": "system", "content": assistant_system_prompt() },
            { "role": "user", "content": build_openai_input(context, request) }
        ],
    });
    let mut request_builder = client
        .post(format!(
            "{}/chat/completions",
            config.base_url.trim_end_matches('/')
        ))
        .json(&payload);
    if let Some(api_key) = &config.api_key {
        request_builder = request_builder.bearer_auth(api_key);
    }
    let response: serde_json::Value = request_builder
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    extract_chat_completion_text(&response).ok_or_else(|| {
        BakulaError::Processing("OpenAI-compatible helpdesk nevrátil textovou odpověď.".to_string())
    })
}

async fn answer_with_ollama(
    config: &LlmConfig,
    context: &AssistantContext,
    request: &AssistantRequest,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("bakula-program/0.1")
        .timeout(llm_timeout(22))
        .build()?;
    let payload = serde_json::json!({
        "model": config.model,
        "stream": false,
        "think": false,
        "messages": [
            { "role": "system", "content": assistant_system_prompt() },
            { "role": "user", "content": build_openai_input(context, request) }
        ],
        "options": {
            "temperature": 0.2,
            "top_p": 0.8,
            "repeat_penalty": 1.05,
            "num_ctx": 8192,
            "num_predict": 520
        }
    });
    let response: serde_json::Value = client
        .post(format!(
            "{}/api/chat",
            config.base_url.trim_end_matches('/')
        ))
        .json(&payload)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    response
        .get("message")
        .and_then(|item| item.get("content"))
        .and_then(|item| item.as_str())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            BakulaError::Processing("Ollama helpdesk nevrátil textovou odpověď.".to_string())
        })
}

async fn answer_with_ollama_stream(
    config: &LlmConfig,
    context: &AssistantContext,
    request: &AssistantRequest,
    tx: &mpsc::Sender<AssistantStreamEvent>,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("bakula-program/0.1")
        .timeout(llm_timeout(75))
        .build()?;
    let payload = serde_json::json!({
        "model": config.model,
        "stream": true,
        "think": false,
        "messages": [
            { "role": "system", "content": assistant_system_prompt() },
            { "role": "user", "content": build_openai_input(context, request) }
        ],
        "options": {
            "temperature": 0.12,
            "top_p": 0.78,
            "repeat_penalty": 1.08,
            "num_ctx": 12288,
            "num_predict": 760,
            "num_gpu": -1
        }
    });
    let mut response = client
        .post(format!(
            "{}/api/chat",
            config.base_url.trim_end_matches('/')
        ))
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;
    let mut buffer = String::new();
    let mut answer = String::new();
    while let Some(chunk) = response.chunk().await? {
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(pos) = buffer.find('\n') {
            let line = buffer[..pos].trim().to_string();
            buffer = buffer[pos + 1..].to_string();
            if line.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if value
                .get("done")
                .and_then(|item| item.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let Some(text) = value
                .get("message")
                .and_then(|item| item.get("content"))
                .and_then(|item| item.as_str())
            else {
                continue;
            };
            let visible = clean_stream_chunk(text);
            if visible.is_empty() {
                continue;
            }
            answer.push_str(&visible);
            tx.send(AssistantStreamEvent {
                event_type: "chunk".to_string(),
                text: Some(visible),
                mode: None,
                sources: Vec::new(),
                error: None,
            })
            .await
            .ok();
        }
    }
    if !buffer.trim().is_empty() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(buffer.trim()) {
            if let Some(text) = value
                .get("message")
                .and_then(|item| item.get("content"))
                .and_then(|item| item.as_str())
            {
                let visible = clean_stream_chunk(text);
                answer.push_str(&visible);
                if !visible.is_empty() {
                    tx.send(AssistantStreamEvent {
                        event_type: "chunk".to_string(),
                        text: Some(visible),
                        mode: None,
                        sources: Vec::new(),
                        error: None,
                    })
                    .await
                    .ok();
                }
            }
        }
    }
    Ok(answer)
}

async fn emit_text_chunks(tx: &mpsc::Sender<AssistantStreamEvent>, text: &str) {
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.len() + word.len() > 32 && !current.is_empty() {
            tx.send(AssistantStreamEvent {
                event_type: "chunk".to_string(),
                text: Some(format!("{current} ")),
                mode: None,
                sources: Vec::new(),
                error: None,
            })
            .await
            .ok();
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        tx.send(AssistantStreamEvent {
            event_type: "chunk".to_string(),
            text: Some(current),
            mode: None,
            sources: Vec::new(),
            error: None,
        })
        .await
        .ok();
    }
}

fn clean_stream_chunk(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("<think") || lower.contains("thinking") || lower.contains("done thinking") {
        clean_model_answer(text)
    } else {
        text.to_string()
    }
}

fn llm_timeout(default_secs: u64) -> Duration {
    let seconds = env_text("BAKULA_LLM_TIMEOUT_SECONDS")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_secs)
        .clamp(3, 120);
    Duration::from_secs(seconds)
}

fn assistant_system_prompt() -> &'static str {
    ai::skoky_system_prompt()
}

fn build_openai_input(context: &AssistantContext, request: &AssistantRequest) -> String {
    let history = request
        .history
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|turn| format!("{}: {}", turn.role, turn.text))
        .collect::<Vec<_>>()
        .join("\n");
    let context_json = serde_json::json!({
        "beh": context.run_name,
        "scope": context.scope,
        "souhrn": context.summary_line,
        "ai_znalostni_balicek": ai::training_pack(),
        "verejne_databaze": intel::public_intel_sources(),
        "vybrany_host": context.selected_host.as_ref().map(|host| serde_json::json!({
            "nazev": host.name,
            "ip": host.ip,
            "sluzby": host.services.iter().map(|service| serde_json::json!({
                "sluzba": service.label,
                "produkt": service.product,
                "verze": service.version,
                "priorita": service.priorita,
                "cve": service.cves.iter().map(|cve| &cve.cve_id).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })),
        "vybrana_sluzba": context.selected_service.as_ref().map(|service| serde_json::json!({
            "sluzba": service.label,
            "produkt": service.product,
            "verze": service.version,
            "priorita": service.priorita,
            "cpe": service.cpe,
            "cve": service.cves.iter().map(|cve| serde_json::json!({
                "id": cve.cve_id,
                "summary": cve.summary,
                "source": cve.source,
                "cvss": cve.cvss.as_ref().map(|cvss| serde_json::json!({
                    "version": cvss.version,
                    "score": cvss.base_score,
                    "severity": cvss.severity,
                })),
                "epss": cve.exploit_context.as_ref().and_then(|context| context.epss.as_ref()).map(|epss| serde_json::json!({
                    "score": epss.score,
                    "percentile": epss.percentile,
                    "date": epss.date,
                })),
                "kev": cve.exploit_context.as_ref().and_then(|context| context.cisa_kev.as_ref()).map(|kev| serde_json::json!({
                    "known_exploited": kev.known_exploited,
                    "name": kev.vulnerability_name,
                    "required_action": kev.required_action,
                })),
                "references": cve.references,
            })).collect::<Vec<_>>(),
        })),
        "vybrany_asset": context.selected_asset.as_ref().map(|asset| serde_json::json!({
            "nazev": asset.name,
            "typ": asset.asset_type,
            "zdroj": asset.source,
            "ip": asset.ip,
            "vendor": asset.vendor,
            "model": asset.model,
        })),
        "vybrany_nalez": context.selected_finding.as_ref().map(|finding| serde_json::json!({
            "id": finding.finding_id,
            "title": finding.title,
            "rationale": finding.rationale,
            "recommendation": finding.recommendation,
            "severity": finding.severity,
            "host_key": finding.host_key,
            "service_key": finding.service_key,
            "dukazy": finding.evidence,
        })),
        "vybrana_akce": context.selected_action.as_ref().map(|action| serde_json::json!({
            "id": action.action_id,
            "title": action.title,
            "rationale": action.rationale,
            "priority": action.priority,
            "tools": action.recommended_tools,
            "dukazy": action.evidence,
        })),
        "top_nalezy": context.top_findings.iter().map(|finding| serde_json::json!({
            "id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity,
            "recommendation": finding.recommendation,
            "dukazy": finding.evidence,
        })).collect::<Vec<_>>(),
        "agentni_rozhodovani": context.decision_lanes.iter().map(|lane| serde_json::json!({
            "zdroj": lane.source,
            "title": lane.title,
            "stav": lane.status,
            "souhrn": lane.summary,
            "dukazy": lane.evidence,
            "nastroje": lane.recommended_tools,
        })).collect::<Vec<_>>(),
        "zdroje": context.sources.iter().map(|source| serde_json::json!({
            "label": source.label,
            "url": source.url,
        })).collect::<Vec<_>>(),
    });
    format!(
        "/no_think\n{}\n\nKontext běhu:\n{}\n\nPoslední konverzace:\n{}\n\nDotaz uživatele:\n{}",
        ai::training_context_block(),
        serde_json::to_string_pretty(&context_json).unwrap_or_default(),
        history,
        request.prompt
    )
}

fn clean_model_answer(text: &str) -> String {
    ai::clean_visible_thinking(text)
}

fn extract_openai_text(value: &serde_json::Value) -> Option<String> {
    if let Some(text) = value.get("output_text").and_then(|item| item.as_str()) {
        if !text.trim().is_empty() {
            return Some(text.trim().to_string());
        }
    }
    value.get("output")?.as_array().and_then(|items| {
        let text = items
            .iter()
            .flat_map(|item| {
                item.get("content")
                    .and_then(|content| content.as_array())
                    .cloned()
                    .unwrap_or_default()
            })
            .filter(|content| {
                content.get("type").and_then(|item| item.as_str()) == Some("output_text")
            })
            .filter_map(|content| {
                content
                    .get("text")
                    .and_then(|item| item.as_str())
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>()
            .join("\n");
        if text.trim().is_empty() {
            None
        } else {
            Some(text.trim().to_string())
        }
    })
}

fn extract_chat_completion_text(value: &serde_json::Value) -> Option<String> {
    value
        .get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}

fn deterministic_answer(context: &AssistantContext, prompt: &str) -> String {
    let normalized = prompt.to_lowercase();
    if normalized.contains("první") || normalized.contains("prior") {
        if let Some(finding) = context
            .selected_finding
            .as_ref()
            .or_else(|| context.top_findings.first())
        {
            return actionable_finding_answer(finding, "Vidím ho jako první věc k řešení.");
        }
    }

    if normalized.contains("zařízení")
        || normalized.contains("uzel")
        || normalized.contains("stanic")
    {
        if let Some(asset) = &context.selected_asset {
            let vendor = [asset.vendor.clone(), asset.model.clone()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · ");
            return format!(
                "Vybraný prvek je {}. Typ: {}. Zdroj: {}. {}{}",
                asset.name,
                localize_asset_type(&asset.asset_type),
                asset.source,
                asset
                    .ip
                    .as_ref()
                    .map(|ip| format!("IP: {}. ", ip))
                    .unwrap_or_default(),
                if vendor.is_empty() {
                    "Výrobce nebo model v běhu chybí.".to_string()
                } else {
                    format!("Identita: {}.", vendor)
                }
            );
        }
        if let Some(host) = &context.selected_host {
            let services = host
                .services
                .iter()
                .map(|service| service.label.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return format!(
                "Vybraný host je {} na adrese {}. Vidím služby: {}. {}",
                host.name,
                host.ip,
                if services.is_empty() {
                    "bez detailu"
                } else {
                    &services
                },
                context.summary_line
            );
        }
    }

    if normalized.contains("krok")
        || normalized.contains("udělat")
        || normalized.contains("oprav")
        || normalized.contains("řešit")
        || normalized.contains("dělat já")
    {
        if let Some(finding) = &context.selected_finding {
            return actionable_finding_answer(finding, "Tohle je praktický postup pro tebe.");
        }
        if let Some(action) = &context.selected_action {
            let tools = if action.recommended_tools.is_empty() {
                "Bez explicitního nástroje.".to_string()
            } else {
                format!(
                    "Doporučené nástroje: {}.",
                    action.recommended_tools.join(", ")
                )
            };
            return format!(
                "Doporučený krok je {}. Proč: {} {} Po dokončení spusť nový běh a ověř, že se důkaz změnil.",
                action.title,
                shorten(&action.rationale, 180),
                tools
            );
        }
        if let Some(finding) = context.top_findings.first() {
            return actionable_finding_answer(
                finding,
                "Nemáš vybraný nález, beru tedy nejvyšší prioritu.",
            );
        }
    }

    if normalized.contains("agent")
        || normalized.contains("rozhod")
        || normalized.contains("decision")
        || normalized.contains("forenz")
        || normalized.contains("ai")
        || normalized.contains("model")
    {
        if !context.decision_lanes.is_empty() {
            let lanes = context
                .decision_lanes
                .iter()
                .take(4)
                .map(|lane| {
                    let tools = if lane.recommended_tools.is_empty() {
                        "bez nástroje".to_string()
                    } else {
                        lane.recommended_tools
                            .iter()
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    format!(
                        "{}: {} Stav: {}. Nástroje: {}.",
                        lane.source,
                        shorten(&lane.summary, 170),
                        lane.status,
                        tools
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            return format!(
                "Rozhodovací část neběží jen jako textová shoda. Skládá hypotézy z aktivního skenu, pasivní telemetrie, změn mezi běhy a jistoty důkazů. {lanes}"
            );
        }
        return "Agentní vrstva je připravená, ale v tomhle běhu zatím nemá dost rozhodovacích stop. Nejdřív je potřeba dodat aktivní inventář, pasivní data nebo diff proti předchozímu běhu.".to_string();
    }

    if normalized.contains("riziko") || normalized.contains("proč") || normalized.contains("vadí")
    {
        if let Some(finding) = &context.selected_finding {
            return risk_explanation_answer(finding);
        }
        if let Some(service) = &context.selected_service {
            return format!(
                "Na vybrané službě vidím {}. Produkt: {} {}. Navázané CVE: {}.",
                service.label,
                service
                    .product
                    .clone()
                    .unwrap_or_else(|| "bez produktu".to_string()),
                service
                    .version
                    .clone()
                    .unwrap_or_else(|| "bez verze".to_string()),
                if service.cves.is_empty() {
                    "žádné potvrzené".to_string()
                } else {
                    service
                        .cves
                        .iter()
                        .map(|cve| cve.cve_id.clone())
                        .take(4)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
        }
    }

    let lead = context
        .selected_finding
        .as_ref()
        .map(|finding| {
            format!(
                "Jdu podle vybraného nálezu {}. {}",
                localized_finding_title(finding),
                shorten(&localized_finding_reason(finding), 160)
            )
        })
        .or_else(|| {
            context.selected_host.as_ref().map(|host| {
                format!(
                    "Dívám se na {} ({}) a držím se jeho služeb a vazeb.",
                    host.name, host.ip
                )
            })
        })
        .unwrap_or_else(|| {
            format!(
                "Vidím běh {} v rozsahu {}.",
                context.run_name, context.scope
            )
        });

    let priority = context
        .top_findings
        .first()
        .map(|finding| format!("Nejvyšší priorita je {}.", localized_finding_title(finding)))
        .unwrap_or_else(|| "V tomhle běhu nevidím vysoce prioritní nález.".to_string());

    format!(
        "{lead} {priority} {} {}",
        context.summary_line,
        next_step(context)
    )
}

fn next_step(context: &AssistantContext) -> String {
    if let Some(finding) = &context.selected_finding {
        return remediation_steps(finding).join(" ");
    }
    if let Some(action) = &context.selected_action {
        return format!("Teď bych udělal: {}.", action.title);
    }
    "Teď bych otevřel nejvyšší nález a potvrdil, jestli jde o skutečný problém nebo jen identifikační mezeru.".to_string()
}

fn actionable_finding_answer(finding: &FindingSummary, prefix: &str) -> String {
    let steps = remediation_steps(finding);
    let verification = verification_steps(finding);
    let navigation = ui_navigation_steps(finding);
    format!(
        "{prefix}\n\nCíl: {}.\n\nCo vidím: {}\n\nProč to řešit: {}.\n\nKde začít v programu:\n{}\n\nCo udělat teď:\n{}\n\nJak ověřit výsledek:\n{}",
        finding_target(finding),
        shorten(&localized_finding_reason(finding), 220),
        finding_impact(finding),
        navigation.join("\n"),
        steps.join("\n"),
        verification.join("\n"),
    )
}

fn risk_explanation_answer(finding: &FindingSummary) -> String {
    format!(
        "{} má prioritu {}. Potvrzený fakt: {}. Dopad: {}. Nehádej exploity bez dalšího ověření; nejdřív udělej: {}",
        localized_finding_title(finding),
        finding.severity,
        shorten(&localized_finding_reason(finding), 220),
        finding_impact(finding),
        remediation_steps(finding).join(" "),
    )
}

fn finding_target(finding: &FindingSummary) -> String {
    [finding.service_key.clone(), finding.host_key.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" / ")
        .if_empty("neuvedený cíl")
}

trait EmptyFallback {
    fn if_empty(self, fallback: &str) -> String;
}

impl EmptyFallback for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.trim().is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}

fn finding_impact(finding: &FindingSummary) -> String {
    let text = finding_text(finding);
    if text.contains("timeout") || text.contains("retry") || text.contains("flow") {
        return "může jít o přetížení, nestabilní cestu, chybnou službu nebo skenovací aktivitu; bez vysvětlení je to provozní i bezpečnostní signál".to_string();
    }
    if text.contains("telnet") || text.contains("ftp") || text.contains("plaintext") {
        return "přihlášení nebo řízení služby může být v síti čitelné a tím pádem zneužitelné při odposlechu".to_string();
    }
    if text.contains("cve") || text.contains("kev") || text.contains("vulnerab") {
        return "verze nebo identita služby sedí na známé slabiny; reálný dopad závisí na patchi, expozici a dostupnosti služby".to_string();
    }
    if text.contains("swagger")
        || text.contains("metrics")
        || text.contains("debug")
        || text.contains("admin")
    {
        return "služba prozrazuje technické nebo správcovské informace, které mohou usnadnit další útok".to_string();
    }
    "jde o místo, kde chybí jistota nebo je vidět slabší nastavení; řešit se má podle důkazů, ne podle dojmu".to_string()
}

fn remediation_steps(finding: &FindingSummary) -> Vec<String> {
    let text = finding_text(finding);
    let mut steps = vec![
        format!(
            "1. Zapiš si cíl {} a přiřaď ho konkrétnímu vlastníkovi nebo zařízení.",
            finding_target(finding)
        ),
        "2. Ověř, jestli tahle služba nebo komunikace opravdu má v síti existovat.".to_string(),
    ];
    if text.contains("timeout") || text.contains("retry") || text.contains("flow") {
        steps.push("3. V pasivním pohledu si vezmi čas výskytu a zdroj/cíl provozu; stejný čas porovnej s logem firewallu, aplikace a vytížením stroje.".to_string());
        steps.push("4. Když jde o legitimní službu, hledej provozní příčinu: přetížení, restart služby, špatnou síťovou cestu nebo blokaci na firewallu.".to_string());
        steps.push("5. Když legitimní důvod nenajdeš, dočasně omez zdrojovou adresu, zapni Hard režim jen v povoleném rozsahu a spusť nový běh pro potvrzení.".to_string());
    } else if text.contains("telnet") {
        steps.push("3. Vypni Telnet a nahraď ho SSH.".to_string());
        steps.push(
            "4. Do změny omez port 23 jen na správcovský segment, ideálně ho úplně zavři."
                .to_string(),
        );
    } else if text.contains("ftp") {
        steps.push("3. Nahraď FTP za SFTP nebo FTPS.".to_string());
        steps.push(
            "4. Ověř, jestli přes FTP nechodí citlivé soubory nebo přihlašovací údaje.".to_string(),
        );
    } else if text.contains("cve") || text.contains("kev") || text.contains("vulnerab") {
        steps.push("3. Ověř skutečnou verzi služby přímo na serveru, ne jen banner.".to_string());
        steps.push(
            "4. Aplikuj vendor patch nebo dočasně omez přístup firewallem a segmentací."
                .to_string(),
        );
        steps.push("5. Po patchi spusť nový aktivní sken a zkontroluj, že se CVE vazba změnila nebo zmizela.".to_string());
    } else if text.contains("swagger")
        || text.contains("metrics")
        || text.contains("debug")
        || text.contains("admin")
    {
        steps.push(
            "3. Dej rozhraní za autentizaci nebo ho omez jen na interní správce.".to_string(),
        );
        steps.push(
            "4. Zkontroluj, jestli neukazuje tokeny, konfiguraci, endpointy nebo interní verze."
                .to_string(),
        );
    } else if !finding.recommendation.trim().is_empty() {
        steps.push(format!("3. {}.", trim_sentence(&finding.recommendation)));
    }
    steps
}

fn ui_navigation_steps(finding: &FindingSummary) -> Vec<String> {
    let text = finding_text(finding);
    let mut steps = vec![
        "1. Vpravo otevři Rizika a nech vybraný tenhle nález.".to_string(),
        "2. Uprostřed přepni na Čtení, aby šel celý důvod a důkazy přečíst bez zkrácení."
            .to_string(),
    ];
    if text.contains("timeout") || text.contains("retry") || text.contains("flow") {
        steps.push(
            "3. V mapě klikni na stejný uzel a sleduj, jestli se problém váže na jednu službu, nebo na celý host."
                .to_string(),
        );
    } else if text.contains("cve") || text.contains("kev") || text.contains("vulnerab") {
        steps.push(
            "3. Zkontroluj v detailu služby konkrétní produkt, verzi, CVE a jistotu důkazu."
                .to_string(),
        );
    } else {
        steps.push(
            "3. V panelu Kroky zkontroluj doporučené nástroje a spusť nový běh po změně."
                .to_string(),
        );
    }
    steps
}

fn verification_steps(finding: &FindingSummary) -> Vec<String> {
    let text = finding_text(finding);
    let mut steps = vec!["1. Spusť nový běh Bakula nad stejným cílem.".to_string()];
    if text.contains("timeout") || text.contains("retry") || text.contains("flow") {
        steps.push("2. V pasivní části musí zmizet opakované timeout/retry vzory nebo musí mít jasný legitimní důvod.".to_string());
    } else if text.contains("telnet") || text.contains("ftp") || text.contains("plaintext") {
        steps.push("2. V pasivních datech už nesmí být nešifrované přihlašování a aktivní sken nemá vidět původní otevřený port.".to_string());
    } else if text.contains("cve") || text.contains("vulnerab") {
        steps.push("2. Aktivní inventář má ukázat novou verzi nebo menší CVE vazbu.".to_string());
    } else {
        steps.push(
            "2. Nález má zmizet, klesnout v prioritě nebo dostat jasný důkaz, proč je akceptovaný."
                .to_string(),
        );
    }
    steps
}

fn finding_text(finding: &FindingSummary) -> String {
    format!(
        "{} {} {} {}",
        finding.title,
        finding.rationale,
        finding.recommendation,
        finding.evidence.join(" ")
    )
    .to_lowercase()
}

fn trim_sentence(value: &str) -> String {
    value.trim().trim_end_matches('.').to_string()
}

fn context_title(context: &AssistantContext) -> String {
    context
        .selected_finding
        .as_ref()
        .map(localized_finding_title)
        .or_else(|| context.selected_host.as_ref().map(|host| host.name.clone()))
        .or_else(|| {
            context
                .selected_asset
                .as_ref()
                .map(|asset| asset.name.clone())
        })
        .unwrap_or_else(|| context.run_name.clone())
}

fn merge_sources(target: &mut Vec<AssistantSource>, extra: Vec<AssistantSource>) {
    for source in extra {
        push_source(target, source);
    }
}

fn push_source(target: &mut Vec<AssistantSource>, source: AssistantSource) {
    if source.label.is_empty() && source.url.is_none() {
        return;
    }
    let exists = target
        .iter()
        .any(|item| item.label == source.label && item.url == source.url);
    if !exists {
        target.push(source);
    }
}

fn find_host<'a>(report: &'a RunReport, needle: &str) -> Option<&'a HostReport> {
    report
        .hosts
        .iter()
        .find(|host| host.host_key == needle || host.host_id == needle || host.ip == needle)
}

fn find_service<'a>(report: &'a RunReport, needle: &str) -> Option<&'a ServiceReport> {
    report
        .hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .find(|service| service.service_key == needle || service.service_id == needle)
}

fn severity_rank(value: &str) -> usize {
    match value.to_lowercase().as_str() {
        "high" | "vysoka" | "kriticka" => 3,
        "medium" | "stredni" => 2,
        "low" | "nizka" => 1,
        _ => 0,
    }
}

fn severity_text(value: Severity) -> String {
    match value {
        Severity::High => "vysoká".to_string(),
        Severity::Medium => "střední".to_string(),
        Severity::Low => "nízká".to_string(),
    }
}

fn localize_asset_type(value: &str) -> &'static str {
    match value {
        "access-point" => "access point",
        "wireless-client" => "Wi‑Fi klient",
        "switch" => "switch",
        "router" => "router",
        "firewall" => "firewall",
        "endpoint" => "koncové zařízení",
        _ => "zařízení",
    }
}

fn short_source_label(url: &str) -> String {
    url.replace("https://", "")
        .replace("http://", "")
        .split('/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/")
}

fn shorten(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max {
        trimmed.to_string()
    } else {
        let keep = max.saturating_sub(1);
        format!("{}…", trimmed.chars().take(keep).collect::<String>())
    }
}

fn localized_finding_title(finding: &FindingSummary) -> String {
    let text = format!("{} {}", finding.title, finding.rationale).to_lowercase();
    if text.contains("openssh") && text.contains("outdated") {
        "Zastaralá verze OpenSSH".to_string()
    } else if text.contains("basic auth") || text.contains("basic-auth") {
        "Slabě chráněné přihlášení".to_string()
    } else if text.contains("swagger") {
        "Vystavené Swagger rozhraní".to_string()
    } else if text.contains("metrics") {
        "Veřejně dostupné technické metriky".to_string()
    } else if text.contains("directory") {
        "Zapnutý výpis adresáře".to_string()
    } else if text.contains("management") || text.contains("admin") {
        "Viditelné správcovské rozhraní".to_string()
    } else if text.contains("kev") || text.contains("known exploited") {
        "Zneužívaná známá zranitelnost".to_string()
    } else if text.contains("identification") || text.contains("gap") {
        "Neúplná identita služby".to_string()
    } else if text.contains("contains vulnerabilities") || text.contains("vulnerabilities") {
        "Služba s navázanými zranitelnostmi".to_string()
    } else {
        finding.title.clone()
    }
}

fn localized_finding_reason(finding: &FindingSummary) -> String {
    let text = format!("{} {}", finding.title, finding.rationale).to_lowercase();
    if text.contains("openssh") && text.contains("outdated") {
        "Na hostu je vidět zastaralá verze OpenSSH. Dává smysl ověřit verzi a rozhodnout, jestli je potřeba aktualizace.".to_string()
    } else if text.contains("contains vulnerabilities")
        || text.contains("vulnerabilities with high priority")
    {
        "Služba odpovídá verzi, která je navázaná na známé zranitelnosti. To je signál k prioritnímu ověření a případnému patchi.".to_string()
    } else if text.contains("swagger") {
        "Na službě je vidět vývojářské rozhraní. To bývá vhodné držet jen interně.".to_string()
    } else if text.contains("metrics") {
        "Služba prozrazuje interní technické informace. Samy o sobě nemusí být škodlivé, ale dávají zbytečný kontext navíc.".to_string()
    } else if text.contains("basic auth") || text.contains("basic-auth") {
        "Přihlášení spoléhá na slabší přenosovou ochranu. To snižuje důvěru v bezpečnost přístupu."
            .to_string()
    } else if text.contains("directory") {
        "Server ukazuje obsah složky přímo v prohlížeči. To může odhalit soubory nebo strukturu služby.".to_string()
    } else if text.contains("exploited") || text.contains("kev") {
        "Tahle slabina není jen teoretická. Existuje signál, že je reálně zneužívaná.".to_string()
    } else if text.contains("management") || text.contains("admin") {
        "Je vidět správcovské rozhraní. To by mělo být dostupné co nejméně lidem i sítím."
            .to_string()
    } else if text.contains("gap") || text.contains("identification") {
        "Služba odpovídá, ale její identita není dost přesná. Není to důkaz průšvihu, spíš mezera v jistotě.".to_string()
    } else {
        finding.rationale.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deterministic_answer_works_with_sample_report() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("workspace_fullstack");
        let report = Workspace::open(&workspace)
            .expect("workspace")
            .load_report("run-20260408082442-1-0efa89d558394082947b40f7de9a7801")
            .expect("report");
        let context = build_context(
            &report,
            &AssistantRequest {
                prompt: "Co mám řešit jako první?".to_string(),
                detail_panel: Some("findings".to_string()),
                selected_node_id: Some("192.168.56.10".to_string()),
                selected_finding_id: None,
                selected_asset_id: None,
                selected_action_id: None,
                history: Vec::new(),
            },
        );
        let answer = deterministic_answer(&context, "Co mám řešit jako první?");

        assert!(!answer.is_empty());
        assert!(
            answer.contains("priorita") || answer.contains("řešení") || answer.contains("Vidím")
        );
    }

    #[tokio::test]
    async fn deterministic_followup_gives_actionable_repair_steps() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("workspace_fullstack");
        let report = Workspace::open(&workspace)
            .expect("workspace")
            .load_report("run-20260408082442-1-0efa89d558394082947b40f7de9a7801")
            .expect("report");
        let context = build_context(
            &report,
            &AssistantRequest {
                prompt: "no ale jak to opravím".to_string(),
                detail_panel: Some("findings".to_string()),
                selected_node_id: Some("192.168.56.10".to_string()),
                selected_finding_id: None,
                selected_asset_id: None,
                selected_action_id: None,
                history: vec![
                    AssistantTurn {
                        role: "user".to_string(),
                        text: "Co znamená vybrané riziko?".to_string(),
                    },
                    AssistantTurn {
                        role: "assistant".to_string(),
                        text: "Na službě je vidět zvýšené riziko.".to_string(),
                    },
                ],
            },
        );
        let answer = deterministic_answer(&context, "no ale jak to opravím");

        assert!(answer.contains("Co udělat teď"));
        assert!(answer.contains("Jak ověřit výsledek"));
        assert!(answer.contains("Kde začít v programu"));
        assert!(answer.contains("Hard režim") || answer.contains("nový běh"));
        assert!(answer.contains("1."));
    }

    #[test]
    fn llm_auto_mode_is_local_first() {
        let config = llm_config_from_lookup(|key| {
            if key == "OPENAI_API_KEY" {
                Some("remote-key-should-not-win-auto".to_string())
            } else {
                None
            }
        })
        .expect("local config");

        assert_eq!(config.mode_name(), "ollama");
        assert_eq!(config.model, ai::SKOKY_MODEL);
        assert_eq!(config.base_url, "http://127.0.0.1:11434");
        assert!(config.api_key.is_none());
    }

    #[test]
    fn llm_provider_can_be_switched_explicitly() {
        let openai = llm_config_from_lookup(|key| match key {
            "BAKULA_LLM_PROVIDER" => Some("openai".to_string()),
            "OPENAI_API_KEY" => Some("test-key".to_string()),
            "OPENAI_ASSISTANT_MODEL" => Some("gpt-test".to_string()),
            _ => None,
        })
        .expect("openai config");
        assert_eq!(openai.mode_name(), "openai");
        assert_eq!(openai.model, "gpt-test");
        assert_eq!(openai.api_key.as_deref(), Some("test-key"));

        let compatible = llm_config_from_lookup(|key| match key {
            "BAKULA_LLM_PROVIDER" => Some("openai-compatible".to_string()),
            "BAKULA_LLM_BASE_URL" => Some("http://127.0.0.1:8000/v1".to_string()),
            "BAKULA_LOCAL_LLM_MODEL" => Some("Qwen/Qwen3-8B".to_string()),
            _ => None,
        })
        .expect("compatible config");
        assert_eq!(compatible.mode_name(), "openai-compatible");
        assert_eq!(compatible.model, "Qwen/Qwen3-8B");
        assert_eq!(compatible.base_url, "http://127.0.0.1:8000/v1");
    }

    #[test]
    fn model_output_is_stripped_from_thinking_blocks() {
        let answer =
            clean_model_answer("  <think>interní úvaha</think>\nVidím nález a navrhuji ověření.  ");
        assert_eq!(answer, "Vidím nález a navrhuji ověření.");

        let answer = clean_model_answer("Vidím část.\n<think>nedokončená úvaha");
        assert_eq!(answer, "Vidím část.");
    }

    #[test]
    fn assistant_context_contains_decision_lanes_for_model_grounding() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("workspace_fullstack");
        let mut report = Workspace::open(&workspace)
            .expect("workspace")
            .load_report("run-20260408082442-1-0efa89d558394082947b40f7de9a7801")
            .expect("report");
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: "test:decision:risk-ranking".to_string(),
            lane_type: "automation".to_string(),
            source: "decision-risk-ranking".to_string(),
            title: "Decision risk ranking".to_string(),
            status: "ok".to_string(),
            summary: "Seřadil jsem hypotézy podle důkazů a jistoty.".to_string(),
            evidence: vec!["score=0.91 decision=mitigate".to_string()],
            recommended_tools: vec!["zeek".to_string(), "nmap-forensic".to_string()],
        });
        let request = AssistantRequest {
            prompt: "Jak rozhoduje agentní systém?".to_string(),
            detail_panel: Some("monitoring".to_string()),
            selected_node_id: None,
            selected_finding_id: None,
            selected_asset_id: None,
            selected_action_id: None,
            history: Vec::new(),
        };
        let context = build_context(&report, &request);
        assert!(
            context
                .decision_lanes
                .iter()
                .any(|lane| lane.source == "decision-risk-ranking")
        );
        let input = build_openai_input(&context, &request);
        assert!(input.contains("agentni_rozhodovani"));
        assert!(input.contains("score=0.91"));
        assert!(input.contains("ai_znalostni_balicek"));
        assert!(input.contains("Projektový znalostní balík"));
    }
}
