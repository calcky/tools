use std::{env, path::PathBuf, process::Command};

fn main() {
    let mut build = cc::Build::new();
    build
        .files(["src/btf_format.c", "src/count_read.c"])
        .warnings(true);
    if let Ok(include) = std::env::var("BPFMAP_INCLUDE_DIR") {
        build.include(include);
    }
    build.compile("bpfmap_btf");
    let object = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("count.bpf.o");
    if let Some(source) = env::var_os("BPFMAP_BPF_OBJECT") {
        println!(
            "cargo:rerun-if-changed={}",
            PathBuf::from(&source).display()
        );
        std::fs::copy(source, object).expect("copy BPF object");
    } else {
        let triple = Command::new("cc").arg("-dumpmachine").output().expect("cc");
        let status = Command::new(env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into()))
            .args(["-target", "bpfel", "-O2", "-g", "-Wall", "-Werror"])
            .arg(format!(
                "-I/usr/include/{}",
                String::from_utf8_lossy(&triple.stdout).trim()
            ))
            .args(["-c", "bpf/count.bpf.c", "-o"])
            .arg(object)
            .status()
            .expect("run clang");
        assert!(status.success(), "BPF compilation failed");
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        println!("cargo:rustc-link-lib=static=argp");
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-lzstd");
    }
    println!("cargo:rerun-if-changed=src/btf_format.c");
    println!("cargo:rerun-if-changed=src/count_read.c");
    println!("cargo:rerun-if-changed=bpf/count.bpf.c");
    println!("cargo:rerun-if-env-changed=BPFMAP_BPF_OBJECT");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-changed=Cross.toml");
    println!("cargo:rerun-if-changed=ci/Dockerfile.x86_64");
    println!("cargo:rerun-if-changed=ci/Dockerfile.arm64");
    println!("cargo:rerun-if-changed=ci/Dockerfile.arm");
    println!("cargo:rerun-if-env-changed=BPFMAP_INCLUDE_DIR");
}
