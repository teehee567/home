use std::{env, fs, path::Path};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let certs_dir = Path::new(&manifest_dir).join("../out/certs");
    fs::create_dir_all(&certs_dir).unwrap();

    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    fs::write(certs_dir.join("server-cert.der"), server.cert.der()).unwrap();
    fs::write(certs_dir.join("server-key.der"), server.signing_key.serialize_der()).unwrap();

    let client = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    fs::write(certs_dir.join("client-cert.der"), client.cert.der()).unwrap();
    fs::write(certs_dir.join("client-key.der"), client.signing_key.serialize_der()).unwrap();

    println!("cargo::rerun-if-changed=build.rs");
}
