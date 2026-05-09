use std::env;

use embed_manifest::{embed_manifest, manifest::ExecutionLevel, new_manifest};

fn main() {
    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(new_manifest("Noob.Launcher")
            .requested_execution_level(ExecutionLevel::RequireAdministrator))
            .expect("embed manifest");
    }
}
