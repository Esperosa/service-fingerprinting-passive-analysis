param(
    [string]$Workspace = ".\\workspace_thesis_live",
    [string]$ListenHost = "127.0.0.1",
    [int]$Port = 8099
)

$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Nenalezen cargo v PATH."
    }

    if (Test-Path $Workspace) {
        Remove-Item -Recurse -Force $Workspace
    }
    New-Item -ItemType Directory -Force -Path $Workspace | Out-Null

    cargo run -- demo e2e --workspace $Workspace
    cargo run -- overeni spust --workspace $Workspace --scenare (Join-Path $Workspace "simulace") --provider demo

    $serverDir = Join-Path $Workspace "server"
    New-Item -ItemType Directory -Force -Path $serverDir | Out-Null

    $stdout = Join-Path $serverDir "stdout.log"
    $stderr = Join-Path $serverDir "stderr.log"
    $pidFile = Join-Path $serverDir "pid.txt"

    $proc = Start-Process -FilePath cargo `
        -ArgumentList @("run", "--", "server", "spust", "--workspace", $Workspace, "--host", $ListenHost, "--port", "$Port") `
        -PassThru `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden

    $proc.Id | Set-Content $pidFile

    $healthUrl = "http://$ListenHost`:$Port/api/health"
    $uiUrl = "http://$ListenHost`:$Port/"

    $ok = $false
    for ($i = 0; $i -lt 80; $i++) {
        Start-Sleep -Milliseconds 250
        try {
            $null = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
            $ok = $true
            break
        } catch {
        }
    }

    if (-not $ok) {
        throw "Server nenabehl v casovem limitu. Viz $stderr"
    }

    Start-Process $uiUrl

    Write-Host "UI bezi na $uiUrl"
    Write-Host "PID: $($proc.Id)"
    Write-Host "Workspace: $Workspace"
    Write-Host "Logy: $serverDir"
}
finally {
    Pop-Location
}
