param(
    [Parameter(Mandatory = $true)] [string]$SshTarget,   # user@host of the home server
    [string]$DataDir = "/srv/noob/data" # must match the bind path in compose.yml
)
$ErrorActionPreference = "Stop"

# cross compile first
if (-not (Get-Command cross -ErrorAction SilentlyContinue)) {
    Write-Host "installing cross"
    cargo install cross
    if ($LASTEXITCODE -ne 0) { throw "cargo install cross failed" }
}

# docker context over ssh
$existing = docker context ls --format '{{.Name}}'
if ($existing -notcontains 'home') {
    Write-Host "creating docker context 'home'"
    docker context create home --docker "host=ssh://$SshTarget"
    if ($LASTEXITCODE -ne 0) { throw "docker context create failed" }
}

# remote host dir
Write-Host "ensuring $DataDir exists"
ssh $SshTarget "mkdir -p $DataDir"
if ($LASTEXITCODE -ne 0) { throw "could not create $DataDir on the home server" }

# first build
& "$PSScriptRoot/redeploy.ps1"

$hostOnly = ($SshTarget -split '@')[-1]
Write-Host "`ndone. next:"
Write-Host "  - Portainer: Stacks -> Add -> paste deploy/compose.yml, name the stack 'noob'."
Write-Host "  - Set NOOB_SERVER=${hostOnly}:4433 for the desktop client (then relaunch it)."
Write-Host "  - Make sure UDP 4433 is open on the home server's firewall."
