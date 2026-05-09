use anyhow::{Context, Result};
use launcher::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use std::{env, fs, process, thread};

fn main() -> Result<()> {
    let built: PathBuf = env::args_os().nth(1).unwrap().into();
    let extra: Vec<_> = env::args_os().skip(2).collect();

    let is_desktop = built.file_stem().and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("desktop"));

    if !is_desktop {
        let status = Command::new(&built).args(&extra).status()?;
        process::exit(status.code().unwrap_or(1));
    }

    let dest = Path::new(INSTALL_DIR).join(DESKTOP_EXE);
    let _ = Command::new("taskkill")
        .args(["/IM", DESKTOP_EXE, "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    thread::sleep(Duration::from_millis(200));
    fs::copy(&built, &dest)
        .with_context(|| format!("copy to {} (run terminal as admin?)", dest.display()))?;
    let _ = Command::new(Path::new(INSTALL_DIR).join(LAUNCHER_EXE)).spawn();
    println!("dev-deploy: {}", dest.display());
    Ok(())
}
