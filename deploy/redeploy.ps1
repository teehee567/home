param([switch]$SkipClient)
$ErrorActionPreference = "Stop"

$target     = "x86_64-unknown-linux-gnu"
$root       = Split-Path -Parent $PSScriptRoot
$context    = "home"
$project    = "noob"
$installDir = "C:\Program Files\Noob"

$endpoint = docker context inspect $context --format '{{.Endpoints.docker.Host}}'
if ($LASTEXITCODE -ne 0) { throw "could not inspect docker context '$context'" }
if ($endpoint -notmatch '^ssh://([^@/]+)@([^/:]+)') { throw "context '$context' endpoint '$endpoint' is not ssh://user@host" }
$sshUser = $Matches[1]
$sshHost = $Matches[2]

if (-not $env:NOOB_DATA_DIR) { $env:NOOB_DATA_DIR = "/home/$sshUser/noob_server/data" }
Write-Host "data dir: $($env:NOOB_DATA_DIR)"

$updateClient = (-not $SkipClient) -and (Test-Path (Join-Path $installDir 'launcher.exe'))
if ($updateClient -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "updating the desktop client writes to $installDir and needs an elevated terminal; re-run as admin, or pass -SkipClient"
}

Push-Location $root
try {
    Write-Host "building"
    cross build --release --target $target -p server
    if ($LASTEXITCODE -ne 0) { throw "cross build failed" }

    Copy-Item "target/$target/release/server" "$PSScriptRoot/server" -Force

    Write-Host "deploying"
    docker --context $context compose -p $project -f "$PSScriptRoot/compose.yml" up -d --build --force-recreate
    if ($LASTEXITCODE -ne 0) { throw "remote compose up failed" }

    Write-Host "logs"
    docker --context $context compose -p $project -f "$PSScriptRoot/compose.yml" logs --tail=20 server

    if ($updateClient) {
        Write-Host "updating desktop client (kill + reinstall + relaunch)"
        # $env:NOOB_SERVER = "${sshHost}:4433"
        cargo run --release -p desktop # let runner work
        if ($LASTEXITCODE -ne 0) { throw "desktop client build/relaunch failed" }
    }
    elseif (-not $SkipClient) {
        Write-Host "client not installed at $installDir; skipping (install the MSI from installer/build.ps1 first)"
    }
}
finally {
    Pop-Location
}
