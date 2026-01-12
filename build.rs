use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("ucp_handler_descriptor.bin");

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(&["proto/ucp_handler/v1/ucp_handler.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/ucp_handler/v1/ucp_handler.proto");

    Ok(())
}
