$ErrorActionPreference = "Stop"

$target  = "x86_64-unknown-linux-gnu"
$root    = Split-Path -Parent $PSScriptRoot
$context = "home"
$project = "noob"

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
