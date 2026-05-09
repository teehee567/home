use std::env;

use embed_manifest::{embed_manifest, manifest::ExecutionLevel, new_manifest};

fn main() {
    slint_build::compile("ui/app.slint").unwrap();

    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("Noob.Desktop")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("embed manifest");
        winres::WindowsResource::new()
            .set_icon("../../data/icons/noob.ico")
            .compile()
            .expect("embed icon");
    }
}
