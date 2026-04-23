# Skoky local AI profile

Skoky je lokální vysvětlovací model pro Bakula UI. Používám ho jako český helpdesk nad jedním auditním během, ne jako zdroj nových faktů.

Základ je `qwen3:8b`, protože dává rozumný poměr velikosti, češtiny, instrukčního chování a lokálního běhu přes Ollama. Projektový model `bakula-skoky:latest` se vytvoří z `Modelfile`, kde je pevně nastavený systémový prompt, nižší teplota a delší kontext pro report.

Spuštění:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-skoky-ai.ps1 -Pull
```

Ověření:

```powershell
cargo run -- ai diagnostika
cargo run -- ai test --prompt "Co mám řešit jako první?"
```
