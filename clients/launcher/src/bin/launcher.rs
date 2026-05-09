#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use launcher::*;
use std::path::Path;
use std::process::Command;

fn main() {
    let exe = Path::new(INSTALL_DIR).join(DESKTOP_EXE);
    let _ = Command::new(exe).spawn();
}
