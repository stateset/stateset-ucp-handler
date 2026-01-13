use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let header_path = manifest_dir.join("../ucp.h");
    let config = cbindgen::Config::from_root_or_default(&manifest_dir);

    if let Ok(bindings) = cbindgen::generate_with_config(&manifest_dir, config) {
        bindings.write_to_file(header_path);
    }

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
