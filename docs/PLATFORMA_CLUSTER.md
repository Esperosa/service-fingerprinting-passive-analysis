# Platform backend, RBAC a cluster scheduler

Tato vrstva doplnuje puvodni pipeline o provozni funkcionalitu, ktera v prototypu chybela:

- centralni perzistentni backend
- role a opravneni
- vydavani a overovani tokenu
- frontu jobu
- worker uzly
- leader/follower lease

## Co je implementovano

### Centralni backend

- SQLite databaze s `WAL` rezimem
- tabulky:
  - `users`
  - `api_tokens`
  - `jobs`
  - `nodes`

### RBAC

Podporovane role:

- `admin`
- `operator`
- `analyst`
- `viewer`

Opravneni jsou deterministicka a odvozena z role. `admin` ma `*`, ostatni role dostavaji jen potrebne read/write scopes.

### Distribuovane planovani

Job je ulozen jako serializovana `PipelineJobSpec` a worker jej claimne pomoci lease:

- `queued`
- `scheduled`
- `running`
- `succeeded`
- `failed`

Worker claimuje jen due joby. Recurring job se po dokonceni vraci do `scheduled`.

### Cluster orchestracni minimum

Kazdy worker node:

- zapisuje heartbeat do `nodes`
- pokousi se ziskat leader lease
- leader muze zpracovavat i periodicke joby
- follower zustava pripraven k prevzeti po vyprseni lease

## Dolozene chovani

Bylo ověřeno:

- vytvoreni uzivatelu a tokenu
- ochrana API pres RBAC tokeny
- enqueue jobu do DB
- worker claim a zpracovani jobu
- leader/follower stav dvou uzlu
- dotazy na `/api/platform/cluster`, `/api/platform/jobs`, `/api/platform/users`

## Poctiva hranice

Tato implementace je provozni krok dopredu, ale porad to neni plnohodnotny cloud-native cluster manager. Chybi hlavne:

- externi SQL backend typu PostgreSQL
- rolling upgrades a quorum management
- multi-region HA
- service mesh / mTLS mezi uzly
- oddelene scheduler/executor pooly
- durable queue broker

Na druhou stranu uz to neni jen lokální workspace-only prototyp; joby, identity i stav uzlu jsou perzistentni a ověřitelne.
