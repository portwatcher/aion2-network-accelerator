fn main() {
    // Ensure the binaries resource dir exists so tauri_build doesn't fail.
    // The real binaries are built by beforeDevCommand / beforeBuildCommand
    // in tauri.conf.json. These placeholders are only a fallback for plain
    // `cargo build` outside of `cargo tauri`.
    let binaries_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries");
    let _ = std::fs::create_dir_all(&binaries_dir);

    for name in &["aion2-relay", "aion2-proxy.exe", "wintun.dll"] {
        let path = binaries_dir.join(name);
        if !path.exists() {
            let _ = std::fs::write(&path, b"placeholder");
        }
    }

    tauri_build::try_build(
        tauri_build::Attributes::new().windows_attributes(
            tauri_build::WindowsAttributes::new()
                .app_manifest(include_str!("aion2-app.exe.manifest")),
        ),
    )
    .expect("failed to run tauri_build");
}
