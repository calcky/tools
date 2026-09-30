use std::{env, path::PathBuf, process::Command};

fn main() {
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        println!("cargo:rustc-link-lib=static=argp");
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-lzstd");
    } else {
        println!("cargo:rustc-link-lib=static=zstd");
    }
    println!("cargo:rerun-if-changed=bpf/observe.bpf.c");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-env-changed=XSKTOP_BPF_OBJECT");
    if let Some(object) = env::var_os("XSKTOP_BPF_OBJECT") {
        println!(
            "cargo:rerun-if-changed={}",
            PathBuf::from(&object).display()
        );
        std::fs::copy(object, out.join("observe.bpf.o")).expect("copy BPF object");
        return;
    }
    let compiler = env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into());
    let triple = Command::new("cc")
        .arg("-dumpmachine")
        .output()
        .expect("cc -dumpmachine");
    assert!(triple.status.success());
    let triple = String::from_utf8(triple.stdout).expect("compiler triple");
    let status = Command::new(compiler)
        .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
        .arg(format!("-I/usr/include/{}", triple.trim()))
        .args(["-c", "bpf/observe.bpf.c", "-o"])
        .arg(out.join("observe.bpf.o"))
        .status()
        .expect("run BPF clang");
    assert!(status.success(), "BPF compilation failed");
}
