#!/usr/bin/env pwsh
param([string]$Version = "0.1.0")

$ErrorActionPreference = "Stop"
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo   = Split-Path -Parent $here
$bindir  = Join-Path $repo "target\release"
$icon    = Join-Path $repo "data\icons\noob.ico"
$logo    = Join-Path $repo "data\icons\smaller_noob.png"
$sidebar = Join-Path $repo "data\icons\larger_noob.png"
$out     = Join-Path $here "Noob-$Version.msi"

& cargo build --release -p launcher --bin launcher --bin postinstall
if ($LASTEXITCODE -ne 0) { throw "cargo build launcher failed" }
& cargo build --release -p desktop
if ($LASTEXITCODE -ne 0) { throw "cargo build desktop failed" }

& wix build (Join-Path $here "Noob.wxs") -arch x64 -acceptEula wix7 -d "BinDir=$bindir" -d "Icon=$icon" -d "Version=$Version" -o $out
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

& wix extension add -g WixToolset.BootstrapperApplications.wixext -acceptEula wix7
if ($LASTEXITCODE -ne 0) { throw "wix extension add failed" }

$setup = Join-Path $here "Noob-$Version-Setup.exe"
& wix build (Join-Path $here "Bundle.wxs") -ext WixToolset.BootstrapperApplications.wixext -arch x64 -acceptEula wix7 -d "MsiPath=$out" -d "Icon=$icon" -d "LogoPng=$logo" -d "SidebarPng=$sidebar" -d "Version=$Version" -o $setup
if ($LASTEXITCODE -ne 0) { throw "wix bundle build failed" }

Write-Host "Built $out"
Write-Host "Built $setup"
