# home

## Build & install (Windows)

```pwsh
./installer/build.ps1 # build everything + Noob-0.1.0.msi
./installer/build.ps1 -Version 0.1.1 # bump version
msiexec /i installer\Noob-0.1.0.msi # install (admin)
msiexec /x installer\Noob-0.1.0.msi # uninstall
```

The MSI installs to `C:\Program Files\Noob`, registers a logon scheduled task
(`Noob`, HIGHEST) that runs `launcher.exe`, and launcher respawns `desktop.exe`
whenever it exits.

## Dev loop

`.cargo/config.toml` wires `cargo run` to `dev-runner`. After the MSI is
installed once:

```pwsh
cargo run -p desktop # builds, writes path to %PROGRAMDATA%\Noob\desktop.path, kills running desktop.exe — launcher respawns the new one
cargo run -p server # any other bin runs normally
```

## Server setup dev loop

Runs the `server` binary on the home box, deployed from dev PC over SSH.

```pwsh
./deploy/setup.ps1 -SshTarget you@<home-ip>  # once: first setup
./deploy/redeploy.ps1 # every update full build and send over
```

After setup: in Portainer add a stack from `deploy/compose.yml` (name it `noob`); set
`NOOB_SERVER=<home-ip>:4433` for the desktop client; open **UDP 4433** on the server firewall.

### Important
- Certs are compile time pinned and shared, both sides need to be rebuilt to use client an server,
- Port 4433 is UDP for QUIC
- db is host bound