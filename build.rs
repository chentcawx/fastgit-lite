use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=resources/app.manifest");
    println!("cargo:rerun-if-changed=config/appsettings.json");
    println!("cargo:rerun-if-changed=config/appsettings");

    let target = env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=FASTGITHUB_BUILD_TARGET={target}");
    println!("cargo:rustc-env=FASTGITHUB_BUILD_PROFILE={}", env::var("PROFILE").unwrap_or_default());

    if !target.starts_with("i686-") {
        println!("cargo:warning=交付目标为 Windows 10 32 位 x86 (i686-pc-windows-msvc)；当前目标为 {target}");
    }

    // Embed the explicit asInvoker / no-UAC manifest on MSVC targets.
    // `#![windows_subsystem = "windows"]` in main.rs sets the GUI subsystem;
    // this manifest documents and pins the execution level and OS support.
    if target.ends_with("-msvc") {
        let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
            .join("resources")
            .join("app.manifest");
        if manifest.exists() {
            // /MANIFESTINPUT is only legal together with /MANIFEST:EMBED.
            // Without it the x86 MSVC linker fails with LNK1220.
            println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
            println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        }
    }
}
