# Enterprise backend vrstva

Tato dokumentace shrnuje tri klicove doplňky nad puvodni platformni vrstvu:

- PostgreSQL external SQL backend
- Redis Streams durable queue broker
- quorum-aware rolling upgrade management

## PostgreSQL

Implementace je v [external_sql.rs](D:/Bakula/bakula-program/src/external_sql.rs).

Pouziva tabulky:

- `users`
- `api_tokens`
- `jobs`
- `nodes`
- `ha_policy`

Smysl:

- oddelit control-plane metadata od lokalniho workspace
- ziskat externi SQL backend vhodny pro centralnejsi nasazeni

## Redis Streams

Implementace je v [broker.rs](D:/Bakula/bakula-program/src/broker.rs).

Smysl:

- oddelit dorucovani jobu od DB
- mit durable broker mezi schedulerem a workerem
- umoznit vice workerum cist z jedne fronty

Aktualni model:

- DB zustava zdrojem pravdy pro stav jobu
- Redis slouzi jako durable delivery vrstva
- worker po prevzeti zpravy jeste claimne job v DB lease mechanismem

## HA / rolling upgrades

Implementace je v [platform.rs](D:/Bakula/bakula-program/src/platform.rs).

Doplneny byly:

- `ha_policy`
- verze a desired verze uzlu
- `ready`, `drain_state`, `upgrade_state`
- quorum-aware kandidatni vyber
- `advance_rollout`
- `mark_node_ready`

To umoznuje:

- drzet quorum pri postupnem upgrade
- nevybirat dalsi uzel, pokud uz probiha upgrade nebo by se rozbilo minimum ready uzlu

## Poctiva hranice

Tohle je vyrazne silnejsi nez puvodni prototyp, ale stale to neni kompletní náhrada za:

- Kubernetes control plane
- etcd/raft quorum manager
- service mesh
- cloud load balancer orchestration
- multi-AZ failover stack

Je to ale realny, auditovatelný a otestovaný krok směrem k produkčnímu provozu.
