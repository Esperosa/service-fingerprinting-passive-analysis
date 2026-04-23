param(
  [string]$PgPort = "55432",
  [string]$RedisPort = "56379"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$pgUri = "postgres://bakula:bakula@127.0.0.1:$PgPort/bakula"
$redisUri = "redis://127.0.0.1:$RedisPort/"

function Wait-Postgres {
  param([string]$ContainerName)
  for ($i = 0; $i -lt 30; $i++) {
    docker exec $ContainerName pg_isready -U bakula -d bakula *> $null
    if ($LASTEXITCODE -eq 0) { return }
    Start-Sleep -Seconds 1
  }
  throw "PostgreSQL se nerozbehl vcas."
}

if (docker ps -a --format '{{.Names}}' | Select-String -SimpleMatch 'bakula-pg-proof') {
  docker rm -f bakula-pg-proof | Out-Null
}
if (docker ps -a --format '{{.Names}}' | Select-String -SimpleMatch 'bakula-redis-proof') {
  docker rm -f bakula-redis-proof | Out-Null
}

docker run -d --name bakula-pg-proof -e POSTGRES_USER=bakula -e POSTGRES_PASSWORD=bakula -e POSTGRES_DB=bakula -p "${PgPort}:5432" postgres:16-alpine | Out-Null
docker run -d --name bakula-redis-proof -p "${RedisPort}:6379" redis:7-alpine | Out-Null
Wait-Postgres -ContainerName bakula-pg-proof

if (Test-Path .\workspace_enterpriseproof) { Remove-Item -Recurse -Force .\workspace_enterpriseproof }
if (Test-Path .\workspace_brokerproof) { Remove-Item -Recurse -Force .\workspace_brokerproof }
New-Item -ItemType Directory -Path .\workspace_enterpriseproof | Out-Null
New-Item -ItemType Directory -Path .\workspace_brokerproof | Out-Null

cargo run -- external-sql init --db-uri $pgUri | Out-File .\workspace_enterpriseproof\pg-init.json -Encoding utf8
cargo run -- external-sql user add --db-uri $pgUri --username admin --role admin | Out-File .\workspace_enterpriseproof\pg-user-admin.json -Encoding utf8
cargo run -- external-sql user add --db-uri $pgUri --username viewer --role viewer | Out-File .\workspace_enterpriseproof\pg-user-viewer.json -Encoding utf8
cargo run -- external-sql token issue --db-uri $pgUri --username admin --name admin-cli | Out-File .\workspace_enterpriseproof\pg-token-admin.json -Encoding utf8
cargo run -- external-sql ha set-policy --db-uri $pgUri --quorum 2 --min-ready 2 --batch-size 1 --target-version 2.1.0 | Out-File .\workspace_enterpriseproof\pg-ha-policy.json -Encoding utf8
cargo run -- external-sql ha register-node --db-uri $pgUri --node-id pg-node-a --version 2.0.0 | Out-File .\workspace_enterpriseproof\pg-node-a.json -Encoding utf8
cargo run -- external-sql ha register-node --db-uri $pgUri --node-id pg-node-b --version 2.0.0 | Out-File .\workspace_enterpriseproof\pg-node-b.json -Encoding utf8
cargo run -- external-sql ha register-node --db-uri $pgUri --node-id pg-node-c --version 2.0.0 | Out-File .\workspace_enterpriseproof\pg-node-c.json -Encoding utf8
cargo run -- external-sql job enqueue --db-uri $pgUri --name 'Postgres queued job' | Out-File .\workspace_enterpriseproof\pg-job.json -Encoding utf8
cargo run -- external-sql ha plan --db-uri $pgUri | Out-File .\workspace_enterpriseproof\pg-ha-plan.json -Encoding utf8
cargo run -- external-sql status --db-uri $pgUri | Out-File .\workspace_enterpriseproof\pg-status.json -Encoding utf8

cargo run -- platform init --db .\workspace_brokerproof\platform.sqlite | Out-File .\workspace_brokerproof\broker-init.json -Encoding utf8
cargo run -- simulace generuj --vystup .\workspace_brokerproof\simulace --seed 7 --nahodnych 0 | Out-File .\workspace_brokerproof\simulace.log -Encoding utf8
cargo run -- platform job enqueue-scenario --db .\workspace_brokerproof\platform.sqlite --workspace .\workspace_brokerproof --scenario-dir .\workspace_brokerproof\simulace\zakladni --nazev 'Broker queued run' --scope 192.168.56.0/24 --broker-uri $redisUri | Out-File .\workspace_brokerproof\broker-job.json -Encoding utf8
cargo run -- platform worker run --db .\workspace_brokerproof\platform.sqlite --node-id broker-node-a --once --broker-uri $redisUri | Out-File .\workspace_brokerproof\broker-worker-a.json -Encoding utf8
cargo run -- platform worker run --db .\workspace_brokerproof\platform.sqlite --node-id broker-node-b --once --broker-uri $redisUri | Out-File .\workspace_brokerproof\broker-worker-b.json -Encoding utf8
cargo run -- platform status --db .\workspace_brokerproof\platform.sqlite | Out-File .\workspace_brokerproof\broker-status.json -Encoding utf8

Write-Host "Hotovo."
Write-Host "PostgreSQL proof: $root\\workspace_enterpriseproof"
Write-Host "Redis broker proof: $root\\workspace_brokerproof"
