use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        println!("cargo:rustc-link-lib=static=argp");
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-lzstd");
    } else {
        println!("cargo:rustc-link-lib=static=zstd");
    }
    println!("cargo:rerun-if-changed=bpf/capture.bpf.c");
    println!("cargo:rerun-if-changed=bpf/capture.h");
    println!("cargo:rerun-if-changed=bpf/filter.bpf.h");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-env-changed=XPCAP_BPF_OBJECT");
    if let Some(object) = env::var_os("XPCAP_BPF_OBJECT") {
        println!(
            "cargo:rerun-if-changed={}",
            PathBuf::from(&object).display()
        );
        std::fs::copy(object, out.join("capture.bpf.o")).expect("copy BPF object");
        return;
    }
    let compiler = env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into());
    let triple = Command::new("cc")
        .arg("-dumpmachine")
        .output()
        .expect("cc -dumpmachine");
    assert!(triple.status.success(), "cc -dumpmachine failed");
    let triple = String::from_utf8(triple.stdout).expect("UTF-8 compiler triple");
    let mut cmd = Command::new(compiler);
    cmd.args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
        .arg(format!("-I/usr/include/{}", triple.trim()))
        .args(["-c", "bpf/capture.bpf.c", "-o"])
        .arg(out.join("capture.bpf.o"));
    assert!(
        cmd.status().expect("run clang").success(),
        "BPF build failed"
    );
}
