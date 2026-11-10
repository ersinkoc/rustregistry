use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=rustregistry.rc");
    println!("cargo:rerun-if-changed=../../src-tauri/icons/icon.ico");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = env!("CARGO_PKG_VERSION");
    let version_number = format!("{},0", version.replace('.', ","));
    let icon = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src-tauri/icons/icon.ico");
    let icon = icon.to_str().expect("UTF-8 icon path").replace('\\', "/");
    let resource = include_str!("rustregistry.rc")
        .replace("@ICON@", &icon)
        .replace("@VERSION_NUMBER@", &version_number)
        .replace("@VERSION@", version);
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"))
        .join("rustregistry.rc");
    fs::write(&output, resource).expect("write the Windows resource");
    embed_resource::compile(output, embed_resource::NONE)
        .manifest_required()
        .expect("compile the RustRegistry Windows resources");
}
