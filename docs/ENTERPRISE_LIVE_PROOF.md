# Enterprise live proof

Tento dokument shrnuje dnes skutecne provedene zive overeni nad externimi sluzbami a lokalnimi workspacy.

Reprodukce je skriptem [enterprise-live-proof.ps1](../scripts/enterprise-live-proof.ps1).

## 1. PostgreSQL control-plane backend

Backend byl overen proti dockerizovanemu PostgreSQL:

- image: `postgres:16-alpine`
- connection string: `postgres://bakula:bakula@127.0.0.1:55432/bakula`

Provedene kroky:

- `external-sql init`
- `external-sql user add` pro `admin`
- `external-sql user add` pro `viewer`
- `external-sql token issue`
- `external-sql ha set-policy`
- `external-sql ha register-node` pro tri uzly
- `external-sql job enqueue`
- `external-sql ha plan`
- `external-sql status`

Artefakty (skript je vytvari lokalne; workspaces nejsou soucasti repozitare):

- `workspace_enterpriseproof/pg-init.json`
- `workspace_enterpriseproof/pg-user-admin.json`
- `workspace_enterpriseproof/pg-user-viewer.json`
- `workspace_enterpriseproof/pg-token-admin.json`
- `workspace_enterpriseproof/pg-ha-policy.json`
- `workspace_enterpriseproof/pg-node-a.json`
- `workspace_enterpriseproof/pg-node-b.json`
- `workspace_enterpriseproof/pg-node-c.json`
- `workspace_enterpriseproof/pg-job.json`
- `workspace_enterpriseproof/pg-ha-plan.json`
- `workspace_enterpriseproof/pg-status.json`

Vysledek:

- 2 uzivatele
- 1 queued job
- 3 registrovane nody
- quorum policy `2/2`
- target version `2.1.0`
- 3 eligible rollout kandidati

## 2. Redis durable queue broker

Broker byl overen proti dockerizovanemu Redis:

- image: `redis:7-alpine`
- URI: `redis://127.0.0.1:56379/`

Provedene kroky:

- `platform job enqueue-scenario --broker-uri ...`
- `platform worker run --once --broker-uri ...` na `broker-node-a`
- druhy `platform worker run --once --broker-uri ...` na `broker-node-b`
- `platform status`

Artefakty (skript je vytvari lokalne; workspaces nejsou soucasti repozitare):

- `workspace_brokerproof/broker-init.json`
- `workspace_brokerproof/broker-job.json`
- `workspace_brokerproof/broker-worker-a.json`
- `workspace_brokerproof/broker-worker-b.json`
- `workspace_brokerproof/broker-status.json`
- `workspace_brokerproof/runs/run-20260408162106-1-87ac7a6385ad454c8af221145ce11d8d/report.json`

Vysledek:

- 1 queued job byl brokerem dorucen a uspesne dokonceny
- prvni worker ziskal run id
- druhy worker uz nic nevykonal
- DB stav jobu je `succeeded`
- oba worker uzly se propsaly do cluster evidence

## 3. Quorum a rolling upgrade logika

Automaticky integrovany test `platform_rbac_scheduler_cluster_and_server_work_end_to_end` overuje:

- RBAC
- tokeny
- queue + worker
- leader/follower lease
- HA policy
- candidate plan
- rollout step
- `mark-ready`
- server API autorizaci nad platform endpointy
