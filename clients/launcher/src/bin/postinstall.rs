use launcher::*;
use std::env;
use std::path::Path;
use std::process::{self, Command};

const TASK_XML_TEMPLATE: &str = include_str!("noob_task.xml");

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("1") => {
            let user = args.get(2).map(String::as_str).unwrap_or("");
            if user.is_empty() {
                process::exit(2);
            }
            install(user);
        }
        Some("0") => uninstall(),
        _ => process::exit(2),
    }
}

fn install(user: &str) {
    let exe = Path::new(INSTALL_DIR).join(LAUNCHER_EXE);
    let task_xml = TASK_XML_TEMPLATE
        .replace("{SID}", user)
        .replace("{EXE}", &exe.display().to_string());

    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Register-ScheduledTask -TaskName $env:NOOB_TASK_NAME -Xml $env:NOOB_TASK_XML -Force | Out-Null",
        ])
        .env("NOOB_TASK_NAME", TASK_LAUNCH)
        .env("NOOB_TASK_XML", &task_xml)
        .status()
        .unwrap();

    if !status.success() {
        process::exit(status.code().unwrap_or(1));
    }
    let _ = Command::new("schtasks").args(["/Run", "/TN", TASK_LAUNCH]).status();
}

fn uninstall() {
    let _ = Command::new("schtasks").args(["/Delete", "/TN", TASK_LAUNCH, "/F"]).status();
    let _ = Command::new("taskkill").args(["/IM", LAUNCHER_EXE, "/F"]).status();
    let _ = Command::new("taskkill").args(["/IM", DESKTOP_EXE, "/F"]).status();
}
