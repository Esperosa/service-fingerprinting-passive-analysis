# Core Evaluation Report

Datum: `2026-04-09`

## Co bylo přidáno

- nový příkaz `bakula evaluace spust`
- paralelní benchmark nad generovanými scénáři se skupinováním závislých běhů
- metriky přesnosti jádra:
  - `core_precision`
  - `core_recall`
  - `core_f1`
  - `average_findings_per_target`
  - `max_finding_families_per_target`
- ukládání evaluace do:
  - `workspace/evaluation/latest.json`
  - `workspace/evaluation/latest.md`

## Opravy před finálním benchmarkem

1. Simulační generátor používal časové posuny po `5` minutách na scénář. U větších sad tím část pasivních událostí vypadla z pasivního okna.
   - oprava v `src/simulation.rs`
2. Finding `unexpected_traffic` se hlásil i tam, kde už byl tentýž cíl vysvětlený jako `new_exposed_service`.
   - oprava v `src/findings.rs`
3. Finding `http_basic_without_tls` se v části změnových scénářů hlásil jako samostatný core finding i tehdy, když šlo o nově exponovanou službu a hlavní problém už byl pokryt diffem.
   - omezení šumu v `src/findings.rs`

## Finální velký benchmark

Příkaz:

```powershell
.\target\debug\bakula-program.exe evaluace spust `
  --workspace .\workspace_eval_mass3 `
  --seed 17 `
  --nahodnych 120 `
  --workers 12 `
  --provider demo
```

Výstupy:

- `workspace_eval_mass3/evaluation/latest.json`
- `workspace_eval_mass3/evaluation/latest.md`
- `workspace_eval_mass3/verification/latest.json`

Wall time:

- `4.072 s`

Souhrn:

- scénáře celkem: `242`
- scénáře prošlé: `242`
- check pass ratio: `1.000`
- core precision: `0.988`
- core recall: `1.000`
- core F1: `0.994`
- average findings / scenario: `6.975`
- average findings / target: `1.399`
- max finding families / target: `2`

## Interpretace

Jádro teď na benchmarku:

- neztrácí očekávané core problémy (`recall = 1.0`)
- nevytváří široké shluky konkurenčních diagnóz na jednom cíli
- drží maximálně `2` finding rodiny na cíl i v horších scénářích

Zbytkový šum:

- `10` případů `http_basic_without_tls` navíc v části změnových scénářů
- jde o malé množství oproti `847` očekávaným core typům

Praktický závěr:

- jádro už se chová jako přesný klasifikátor hlavního problému, ne jako generátor mnoha rovnocenných možností
- další zlepšení dává smysl hlavně v oddělení `core finding` vs. `supporting evidence`, ne v dalším rozšiřování pravidel
