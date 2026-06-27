$ErrorActionPreference = "Stop"

$target  = "x86_64-unknown-linux-gnu"
$root    = Split-Path -Parent $PSScriptRoot
$context = "home"
$project = "noob"

if (-not $env:NOOB_DATA_DIR) {
    $endpoint = docker context inspect $context --format '{{.Endpoints.docker.Host}}'
    if ($LASTEXITCODE -ne 0) { throw "could not inspect docker context '$context'" }
    if ($endpoint -notmatch '^ssh://([^@/]+)@') { throw "context '$context' endpoint '$endpoint' is not ssh://user@host" }
    $env:NOOB_DATA_DIR = "/home/$($Matches[1])/noob_server/data"
}
Write-Host "data dir: $($env:NOOB_DATA_DIR)"

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
}
finally {
    Pop-Location
}
