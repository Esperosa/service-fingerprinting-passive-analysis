# Enterprise live proof

Tento dokument shrnuje dnes skutecne provedene zive overeni nad externimi sluzbami a lokalnimi workspacy.

Reprodukce je skriptem [enterprise-live-proof.ps1](D:/Bakula/bakula-program/scripts/enterprise-live-proof.ps1).

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

Artefakty:

- [pg-init.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-init.json)
- [pg-user-admin.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-user-admin.json)
- [pg-user-viewer.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-user-viewer.json)
- [pg-token-admin.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-token-admin.json)
- [pg-ha-policy.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-ha-policy.json)
- [pg-node-a.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-node-a.json)
- [pg-node-b.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-node-b.json)
- [pg-node-c.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-node-c.json)
- [pg-job.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-job.json)
- [pg-ha-plan.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-ha-plan.json)
- [pg-status.json](D:/Bakula/bakula-program/workspace_enterpriseproof/pg-status.json)

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

Artefakty:

- [broker-init.json](D:/Bakula/bakula-program/workspace_brokerproof/broker-init.json)
- [broker-job.json](D:/Bakula/bakula-program/workspace_brokerproof/broker-job.json)
- [broker-worker-a.json](D:/Bakula/bakula-program/workspace_brokerproof/broker-worker-a.json)
- [broker-worker-b.json](D:/Bakula/bakula-program/workspace_brokerproof/broker-worker-b.json)
- [broker-status.json](D:/Bakula/bakula-program/workspace_brokerproof/broker-status.json)
- [report.json](D:/Bakula/bakula-program/workspace_brokerproof/runs/run-20260408162106-1-87ac7a6385ad454c8af221145ce11d8d/report.json)

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
