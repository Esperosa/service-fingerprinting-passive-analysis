use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

use crate::{BakulaError, Result, intel};

pub const SKOKY_MODEL: &str = "bakula-skoky:latest";
pub const SKOKY_BASE_MODEL: &str = "qwen3:8b";
pub const SKOKY_MODELFILE_PATH: &str = "models/skoky/Modelfile";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiModelProfile {
    pub model_name: String,
    pub base_model: String,
    pub runner: String,
    pub purpose: String,
    pub language: String,
    pub recommended_memory: String,
    pub setup_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDiagnostic {
    pub status: String,
    pub profile: AiModelProfile,
    pub ollama_cli_available: bool,
    pub ollama_server_available: bool,
    pub base_model_present: bool,
    pub tuned_model_present: bool,
    pub selected_model: String,
    pub knowledge_rules_total: usize,
    pub training_examples_total: usize,
    pub public_sources_total: usize,
    pub modelfile_sha256: String,
    pub recommended_env: Vec<String>,
    pub gpu_runtime_hint: String,
    pub next_steps: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTrainingExample {
    pub intent: String,
    pub user: String,
    pub assistant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTrainingPack {
    pub pack_id: String,
    pub language: String,
    pub purpose: String,
    pub rules: Vec<String>,
    pub examples: Vec<AiTrainingExample>,
}

pub fn model_profile() -> AiModelProfile {
    AiModelProfile {
        model_name: SKOKY_MODEL.to_string(),
        base_model: SKOKY_BASE_MODEL.to_string(),
        runner: "ollama".to_string(),
        purpose: "Lokální český vysvětlovací chatbot nad auditním během Bakula.".to_string(),
        language: "cs + en, odpovědi primárně česky".to_string(),
        recommended_memory: "cca 8-12 GB RAM podle kvantizace a běžícího prostředí".to_string(),
        setup_command: ".\\scripts\\setup-skoky-ai.ps1 -Pull".to_string(),
    }
}

pub fn training_pack() -> AiTrainingPack {
    AiTrainingPack {
        pack_id: "skoky-cyber-reader-v1".to_string(),
        language: "cs".to_string(),
        purpose:
            "Převádí auditní JSON, nálezy, agentní stopy a telemetrii do srozumitelné češtiny."
                .to_string(),
        rules: vec![
            "Nikdy neuvádím CVE, IP adresu, službu ani důkaz, který není v kontextu.".to_string(),
            "Nejdřív oddělím potvrzený fakt od hypotézy a až potom navrhnu zásah.".to_string(),
            "Vulners API je volitelný doplněk. Základní veřejný kontext stavím z NVD, CISA KEV, FIRST EPSS, CIRCL, OSV.dev a MITRE ATT&CK.".to_string(),
            "U aktivního skenu vysvětlím, co zjistil Nmap a jak jistá je identita služby.".to_string(),
            "U pasivních dat vysvětlím, jestli jde o skutečně pozorovaný provoz, nebo jen chybějící telemetrii.".to_string(),
            "U nešifrovaného přihlášení popíšu riziko pro hesla a navrhnu konkrétní ověření v Zeek/Suricata/flow datech.".to_string(),
            "U agentního rozhodování říkám, který agent má běžet, který nemá běžet a jaký důkaz to změnil.".to_string(),
            "Když se ptám na exploitability, porovnávám CVSS dopad, KEV známé zneužití, EPSS pravděpodobnost, veřejný advisory kontext a reálnou expozici v síti.".to_string(),
            "Pro neajťáka používám praktický jazyk: co vidím, proč to vadí, co udělat teď, jak ověřit výsledek.".to_string(),
        ],
        examples: vec![
            AiTrainingExample {
                intent: "priorita".to_string(),
                user: "Co mám řešit jako první?".to_string(),
                assistant: "Začni nejvyšším potvrzeným rizikem v reportu. Uveď cílový host nebo službu, důvod priority, jeden bezpečný první krok a způsob ověření po změně. Pokud je jistota nízká, nejdřív doporuč ověřovacího agenta místo okamžitého zásahu.".to_string(),
            },
            AiTrainingExample {
                intent: "plaintext-login".to_string(),
                user: "Co znamená nešifrované přihlášení?".to_string(),
                assistant: "Nešifrované přihlášení znamená, že přihlašovací relace může být čitelná v síti. Neříkej, že heslo uniklo, pokud to není v pasivních důkazech. Doporuč vypnout Telnet/FTP, nahradit je SSH/HTTPS a ověřit změnu v Zeek, Suricata nebo flow datech.".to_string(),
            },
            AiTrainingExample {
                intent: "agentni-rozhodovani".to_string(),
                user: "Jak rozhoduje agentní systém?".to_string(),
                assistant: "Vysvětli rozdíl mezi dedukcí z pravidel, indukcí z opakovaných provozních vzorců a abdukcí pro hypotézy s chybějícím důkazem. Uveď konkrétní lane nebo agenta z kontextu a popiš, proč má běžet nebo být vypnutý.".to_string(),
            },
            AiTrainingExample {
                intent: "neuplna-data".to_string(),
                user: "Je výsledek kompletní?".to_string(),
                assistant: "Zkontroluj aktivní inventář, CVE provider, pasivní logy, live flow telemetry, AI stav a exporty. Pokud něco chybí, řekni to přímo jako limit běhu a navrhni, jaký zdroj dat má uživatel připojit.".to_string(),
            },
            AiTrainingExample {
                intent: "verejne-intel-zdroje".to_string(),
                user: "Potřebuju Vulners klíč?".to_string(),
                assistant: "Vulners klíč není povinný. Bez něj používám veřejný základ NVD, CISA KEV, FIRST EPSS, CIRCL, OSV.dev a MITRE ATT&CK kontext. Vulners přidej jako doplněk, když chceš širší advisory a exploit kontext nebo vyšší limit dotazů.".to_string(),
            },
        ],
    }
}

pub fn training_context_block() -> String {
    let pack = training_pack();
    let rules = pack
        .rules
        .iter()
        .map(|rule| format!("- {rule}"))
        .collect::<Vec<_>>()
        .join("\n");
    let examples = pack
        .examples
        .iter()
        .map(|example| {
            format!(
                "- intent={}: user=\"{}\" assistant_rule=\"{}\"",
                example.intent, example.user, example.assistant
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let sources = intel::public_intel_sources()
        .iter()
        .map(|source| {
            format!(
                "- {}: {} key={} default={}",
                source.name,
                source.purpose,
                source.key_env.as_deref().unwrap_or("none"),
                source.enabled_by_default
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Projektový znalostní balík {pack_id}:\nPravidla:\n{rules}\nVeřejné a volitelné intel zdroje:\n{sources}\nPříklady odpovědí:\n{examples}",
        pack_id = pack.pack_id
    )
}

pub fn skoky_system_prompt() -> &'static str {
    "Jsi Skoky, lokální český cybersecurity kopilot nad jedním konkrétním během Bakula. Odpovídej česky, věcně a srozumitelně i pro člověka, který není ajťák. Každá odpověď musí přímo reagovat na poslední dotaz, ne jen zopakovat nález. Drž se jen dodaného JSON kontextu, důkazů, zdrojů a agentních rozhodovacích stop. Rozlišuj potvrzený fakt, pracovní hypotézu, indukci z opakovaných vzorců, dedukci z pravidla a chybějící ověření. Když se uživatel ptá 'jak to opravím' nebo 'co mám dělat já', napiš konkrétní postup v očíslovaných krocích: vlastník cíle, ověření služby, nápravné opatření, ověření po změně. Ber Vulners jako volitelný zdroj; základní veřejný stack je NVD, CISA KEV, FIRST EPSS, CIRCL, OSV.dev a MITRE ATT&CK kontext. Když něco v kontextu není, řekni to stručně a navrhni, jaký zdroj dat to má ověřit. Běžná odpověď má mít 4 až 8 krátkých vět nebo odrážek. Vždy uveď: co vidíš, proč to vadí nebo nevadí, co udělat teď, jak ověřit výsledek. U agentního rozhodování popiš, který agent má smysl spustit, který nechat běžet, který vypnout a proč. Nepiš marketingově, nevymýšlej incidenty, nevytvářej falešné CVE a nezobrazuj interní chain-of-thought, tagy <think> ani text začínající slovem Thinking."
}

pub fn modelfile_contents() -> String {
    let pack = training_pack();
    let examples = pack
        .examples
        .iter()
        .map(|example| {
            format!(
                "MESSAGE user \"\"\"{}\"\"\"\nMESSAGE assistant \"\"\"{}\"\"\"",
                example.user, example.assistant
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"FROM {base}
PARAMETER temperature 0.18
PARAMETER top_p 0.82
PARAMETER repeat_penalty 1.08
PARAMETER num_ctx 12288
PARAMETER num_predict 900
PARAMETER num_gpu -1
SYSTEM """{system}"""
{examples}
"#,
        base = SKOKY_BASE_MODEL,
        system = skoky_system_prompt(),
        examples = examples
    )
}

pub fn write_modelfile(path: &Path) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, modelfile_contents())?;
    Ok(path.to_path_buf())
}

pub fn diagnose() -> AiDiagnostic {
    let profile = model_profile();
    let version = run_ollama(&["--version"]);
    let list = run_ollama(&["list"]);
    let ps = run_ollama(&["ps"]);
    let ollama_cli_available = version.success;
    let ollama_server_available = list.success;
    let models = parse_ollama_list(&list.stdout);
    let base_model_present = has_model(&models, SKOKY_BASE_MODEL);
    let tuned_model_present = has_model(&models, SKOKY_MODEL);
    let pack = training_pack();
    let modelfile = modelfile_contents();
    let public_sources_total = intel::public_intel_sources().len();

    let status = if !ollama_cli_available {
        "missing-ollama"
    } else if !ollama_server_available {
        "ollama-not-running"
    } else if tuned_model_present {
        "ready"
    } else if base_model_present {
        "base-ready"
    } else {
        "missing-model"
    }
    .to_string();

    let mut evidence = Vec::new();
    if !version.stdout.trim().is_empty() {
        evidence.push(version.stdout.trim().to_string());
    }
    if !version.stderr.trim().is_empty() {
        evidence.push(version.stderr.trim().to_string());
    }
    if ps.success && !ps.stdout.trim().is_empty() {
        evidence.push(ps.stdout.trim().to_string());
    }
    evidence.push(format!("models={}", models.join(",")));
    let gpu_runtime_hint = if ps.stdout.to_ascii_lowercase().contains("gpu") {
        "Ollama hlásí běžící model přes GPU runtime.".to_string()
    } else if ps.success {
        "Ollama běží, ale v `ollama ps` není vidět GPU runner; využití GPU závisí na instalaci ovladačů a Ollama.".to_string()
    } else {
        "GPU runtime nejde ověřit, protože `ollama ps` neodpovědělo.".to_string()
    };

    AiDiagnostic {
        status: status.clone(),
        profile,
        ollama_cli_available,
        ollama_server_available,
        base_model_present,
        tuned_model_present,
        selected_model: SKOKY_MODEL.to_string(),
        knowledge_rules_total: pack.rules.len(),
        training_examples_total: pack.examples.len(),
        public_sources_total,
        modelfile_sha256: sha256_hex(modelfile.as_bytes()),
        recommended_env: vec![
            "BAKULA_LLM_PROVIDER=ollama".to_string(),
            format!("OLLAMA_ASSISTANT_MODEL={SKOKY_MODEL}"),
            "BAKULA_LLM_TIMEOUT_SECONDS=45".to_string(),
            "OLLAMA_NUM_GPU=-1".to_string(),
        ],
        gpu_runtime_hint,
        next_steps: next_steps_for_status(&status),
        evidence,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn setup_ollama_model(modelfile_path: &Path, pull_base_model: bool) -> Result<AiDiagnostic> {
    write_modelfile(modelfile_path)?;
    let before = diagnose();
    if !before.ollama_cli_available {
        return Err(BakulaError::Config(
            "Ollama není dostupná v PATH. Nainstaluj Ollama a spusť tento příkaz znovu."
                .to_string(),
        ));
    }
    if !before.ollama_server_available {
        return Err(BakulaError::Config(
            "Ollama CLI existuje, ale server neodpovídá. Spusť Ollama aplikaci nebo službu."
                .to_string(),
        ));
    }
    if !before.base_model_present && pull_base_model {
        require_success(
            run_ollama(&["pull", SKOKY_BASE_MODEL]),
            "Stažení základního modelu qwen3:8b selhalo.",
        )?;
    } else if !before.base_model_present {
        return Err(BakulaError::Config(format!(
            "Základní model {SKOKY_BASE_MODEL} není stažený. Spusť setup s --pull nebo `ollama pull {SKOKY_BASE_MODEL}`."
        )));
    }
    require_success(
        run_ollama(&[
            "create",
            SKOKY_MODEL,
            "-f",
            &modelfile_path.to_string_lossy(),
        ]),
        "Vytvoření projektového modelu bakula-skoky selhalo.",
    )?;
    Ok(diagnose())
}

pub fn smoke_prompt(prompt: &str) -> Result<String> {
    let diagnostic = diagnose();
    if !diagnostic.tuned_model_present {
        return Err(BakulaError::Config(format!(
            "Model {SKOKY_MODEL} není připravený. Spusť `{}`.",
            diagnostic.profile.setup_command
        )));
    }
    let guarded_prompt = format!("/no_think\n{prompt}");
    let output = run_ollama(&["run", SKOKY_MODEL, &guarded_prompt]);
    require_success(output.clone(), "Smoke test lokálního modelu selhal.")?;
    Ok(clean_visible_thinking(&output.stdout))
}

pub fn clean_visible_thinking(text: &str) -> String {
    let mut output = strip_xml_think(text.trim());
    loop {
        let trimmed = output.trim_start();
        let lower = trimmed.to_lowercase();
        let starts_with_thinking =
            lower.starts_with("thinking...") || lower.starts_with("thinking…");
        if !starts_with_thinking {
            break;
        }
        if let Some(done_at) = lower.find("done thinking.") {
            let after_done = done_at + "done thinking.".len();
            output = trimmed[after_done..].trim().to_string();
            continue;
        }
        let mut after_block = Vec::new();
        let mut inside = true;
        for line in trimmed.lines() {
            let line_lower = line.trim().to_lowercase();
            if inside && line_lower.contains("done thinking") {
                inside = false;
                continue;
            }
            if inside {
                continue;
            }
            after_block.push(line);
        }
        output = after_block.join("\n").trim().to_string();
        break;
    }
    output.trim().to_string()
}

fn strip_xml_think(text: &str) -> String {
    let mut output = text.trim().to_string();
    loop {
        let lower = output.to_lowercase();
        let Some(start) = lower.find("<think>") else {
            break;
        };
        let Some(relative_end) = lower[start..].find("</think>") else {
            output.replace_range(start.., "");
            break;
        };
        let end = start + relative_end + "</think>".len();
        output.replace_range(start..end, "");
    }
    output
}

#[derive(Debug, Clone)]
struct CommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_ollama(args: &[&str]) -> CommandOutput {
    match Command::new("ollama").args(args).output() {
        Ok(output) => CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Err(error) => CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: error.to_string(),
        },
    }
}

fn require_success(output: CommandOutput, message: &str) -> Result<()> {
    if output.success {
        return Ok(());
    }
    let detail = [output.stdout.trim(), output.stderr.trim()]
        .into_iter()
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");
    Err(BakulaError::Processing(if detail.is_empty() {
        message.to_string()
    } else {
        format!("{message} {detail}")
    }))
}

fn parse_ollama_list(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(ToString::to_string)
        .collect()
}

fn has_model(models: &[String], expected: &str) -> bool {
    let bare_expected = expected.split(':').next().unwrap_or(expected);
    models
        .iter()
        .any(|model| model == expected || model.split(':').next().unwrap_or(model) == bare_expected)
}

fn next_steps_for_status(status: &str) -> Vec<String> {
    match status {
        "ready" => {
            vec!["Model je připravený. UI chat bude používat bakula-skoky:latest.".to_string()]
        }
        "base-ready" => vec![format!(
            "Základní model existuje. Vytvoř projektový profil příkazem `ollama create {SKOKY_MODEL} -f {SKOKY_MODELFILE_PATH}`."
        )],
        "missing-model" => vec![format!(
            "Stáhni a vytvoř model příkazem `.\\scripts\\setup-skoky-ai.ps1 -Pull`."
        )],
        "ollama-not-running" => {
            vec!["Spusť Ollama aplikaci nebo službu a potom zopakuj diagnostiku.".to_string()]
        }
        _ => vec!["Nainstaluj Ollama a potom spusť setup skript pro Skoky model.".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modelfile_points_to_project_model_base_and_czech_prompt() {
        let modelfile = modelfile_contents();
        assert!(modelfile.contains("FROM qwen3:8b"));
        assert!(modelfile.contains("Jsi Skoky"));
        assert!(modelfile.contains("česky"));
        assert!(modelfile.contains("num_ctx 12288"));
        assert!(modelfile.contains("num_gpu -1"));
        assert!(modelfile.contains("MESSAGE user"));
        assert!(modelfile.contains("nešifrované přihlášení"));
    }

    #[test]
    fn training_pack_contains_domain_rules_and_examples() {
        let pack = training_pack();
        assert!(pack.rules.len() >= 6);
        assert!(
            pack.examples
                .iter()
                .any(|example| example.intent == "priorita")
        );
        assert!(training_context_block().contains("Projektový znalostní balík"));
    }

    #[test]
    fn ollama_list_parser_reads_model_names() {
        let models = parse_ollama_list(
            "NAME               ID              SIZE      MODIFIED\nqwen3:8b           abc             5 GB      today\nbakula-skoky:latest def            5 GB      now\n",
        );
        assert!(has_model(&models, "qwen3:8b"));
        assert!(has_model(&models, "bakula-skoky:latest"));
    }

    #[test]
    fn visible_thinking_banner_is_removed() {
        let text = "Thinking...\nTady bych uvazoval.\n...done thinking.\n\nVidím potvrzený nález.";
        assert_eq!(clean_visible_thinking(text), "Vidím potvrzený nález.");
        assert_eq!(
            clean_visible_thinking("<think>tajné</think>\nHotovo."),
            "Hotovo."
        );
    }
}
