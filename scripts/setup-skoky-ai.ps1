param(
    [switch]$Pull,
    [string]$ModelFile = "models/skoky/Modelfile",
    [string]$BaseModel = "qwen3:8b",
    [string]$ProjectModel = "bakula-skoky:latest"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    throw "Ollama neni v PATH. Nainstaluj Ollama, spust ji a pak opakuj setup."
}

$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$modelFilePath = Resolve-Path -LiteralPath (Join-Path $root $ModelFile)

Write-Host "Kontroluji Ollama runtime..."
ollama --version

if ($Pull) {
    Write-Host "Stahuji zakladni model $BaseModel..."
    ollama pull $BaseModel
}

$models = ollama list
if (($models -join "`n") -notmatch [regex]::Escape($BaseModel.Split(":")[0])) {
    throw "Zakladni model $BaseModel neni stazeny. Spust tento skript s parametrem -Pull."
}

Write-Host "Vytvarim projektovy model $ProjectModel z $modelFilePath..."
ollama create $ProjectModel -f $modelFilePath

Write-Host "Hotovo. Pro Bakula UI nastav:"
Write-Host "`$env:BAKULA_LLM_PROVIDER = `"ollama`""
Write-Host "`$env:OLLAMA_ASSISTANT_MODEL = `"$ProjectModel`""
