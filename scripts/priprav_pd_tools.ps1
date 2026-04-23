$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$ToolsRoot = Join-Path $Root 'tools\projectdiscovery'
$HttpxVersion = '1.9.0'
$NucleiVersion = '3.7.1'
$HttpxZip = "httpx_${HttpxVersion}_windows_amd64.zip"
$NucleiZip = "nuclei_${NucleiVersion}_windows_amd64.zip"
$HttpxChecksums = "httpx_${HttpxVersion}_checksums.txt"
$NucleiChecksums = "nuclei_${NucleiVersion}_checksums.txt"

New-Item -ItemType Directory -Force -Path $ToolsRoot | Out-Null

function Download-IfMissing {
    param(
        [string]$Url,
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        Invoke-WebRequest -UseBasicParsing $Url -OutFile $Path
    }
}

function Assert-Checksum {
    param(
        [string]$ArchivePath,
        [string]$ChecksumsPath
    )
    $name = [System.IO.Path]::GetFileName($ArchivePath)
    $expected = (Get-Content $ChecksumsPath | Where-Object { $_ -match [regex]::Escape($name) } | Select-Object -First 1).Split(' ')[0].Trim().ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLower()
    if ($expected -ne $actual) {
        throw "Checksum nesouhlasi pro $name. Expected=$expected Actual=$actual"
    }
}

$HttpxArchivePath = Join-Path $ToolsRoot $HttpxZip
$HttpxChecksumsPath = Join-Path $ToolsRoot $HttpxChecksums
$NucleiArchivePath = Join-Path $ToolsRoot $NucleiZip
$NucleiChecksumsPath = Join-Path $ToolsRoot $NucleiChecksums

Download-IfMissing "https://github.com/projectdiscovery/httpx/releases/download/v$HttpxVersion/$HttpxZip" $HttpxArchivePath
Download-IfMissing "https://github.com/projectdiscovery/httpx/releases/download/v$HttpxVersion/$HttpxChecksums" $HttpxChecksumsPath
Download-IfMissing "https://github.com/projectdiscovery/nuclei/releases/download/v$NucleiVersion/$NucleiZip" $NucleiArchivePath
Download-IfMissing "https://github.com/projectdiscovery/nuclei/releases/download/v$NucleiVersion/$NucleiChecksums" $NucleiChecksumsPath

Assert-Checksum $HttpxArchivePath $HttpxChecksumsPath
Assert-Checksum $NucleiArchivePath $NucleiChecksumsPath

$HttpxDir = Join-Path $ToolsRoot 'httpx'
$NucleiDir = Join-Path $ToolsRoot 'nuclei'
New-Item -ItemType Directory -Force -Path $HttpxDir | Out-Null
New-Item -ItemType Directory -Force -Path $NucleiDir | Out-Null
Expand-Archive -LiteralPath $HttpxArchivePath -DestinationPath $HttpxDir -Force
Expand-Archive -LiteralPath $NucleiArchivePath -DestinationPath $NucleiDir -Force

$ControlledTemplatesSource = Join-Path $Root 'resources\nuclei-templates\controlled'
$ControlledTemplatesTarget = Join-Path $env:USERPROFILE 'nuclei-templates\bakula-controlled'
New-Item -ItemType Directory -Force -Path $ControlledTemplatesTarget | Out-Null
Copy-Item -Path (Join-Path $ControlledTemplatesSource '*') -Destination $ControlledTemplatesTarget -Force

Write-Host "ProjectDiscovery nastroje a controlled templaty jsou pripraveny."
Write-Host "httpx:   $HttpxDir\httpx.exe"
Write-Host "nuclei:  $NucleiDir\nuclei.exe"
Write-Host "templaty: $ControlledTemplatesTarget"
