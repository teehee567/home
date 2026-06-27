param(
    [Parameter(Mandatory = $true)] [string]$SshTarget,   # user@host of the home server
    [string]$DataDir                                      # defaults to the ssh user's home (see below)
)
$ErrorActionPreference = "Stop"

if (-not $DataDir) { $DataDir = "/home/$(($SshTarget -split '@')[0])/noob_server/data" }
$env:NOOB_DATA_DIR = $DataDir

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

# first build (server only; client install is the one-time MSI, then redeploy.ps1 updates it)
& "$PSScriptRoot/redeploy.ps1" -SkipClient

Write-Host "`ndone. next:"
Write-Host "  - Portainer: Stacks -> Add -> paste deploy/compose.yml, name the stack 'noob'."
Write-Host "  - Install the desktop client once: run installer/build.ps1, then the generated MSI."
Write-Host "  - From then on, deploy/redeploy.ps1 (elevated) redeploys the server AND relaunches the client."
Write-Host "  - Make sure UDP 4433 is open on the home server's firewall."
