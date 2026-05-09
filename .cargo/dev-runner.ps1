param([Parameter(ValueFromRemainingArguments=$true)][string[]]$RunnerArgs)
$ErrorActionPreference = "Stop"
& cargo build --quiet --release -p dev-runner
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$exe = Join-Path $PSScriptRoot "..\target\release\dev-runner.exe"
& $exe @RunnerArgs
exit $LASTEXITCODE
