use std::{env, path::PathBuf, process::Command};

fn main() {
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        println!("cargo:rustc-link-lib=static=argp");
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-lzstd");
    } else {
        let triple = Command::new("cc").arg("-dumpmachine").output().expect("cc");
        println!(
            "cargo:rustc-link-search=native=/usr/lib/{}",
            String::from_utf8(triple.stdout)
                .expect("compiler triple")
                .trim()
        );
        println!("cargo:rustc-link-lib=static=zstd");
    }
    println!("cargo:rerun-if-changed=bpf/observe.bpf.c");
    println!("cargo:rerun-if-env-changed=SKBTOP_BPF_OBJECT");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    if let Some(object) = env::var_os("SKBTOP_BPF_OBJECT") {
        println!(
            "cargo:rerun-if-changed={}",
            PathBuf::from(&object).display()
        );
        std::fs::copy(object, out.join("observe.bpf.o")).expect("copy BPF object");
        return;
    }
    let triple = Command::new("cc").arg("-dumpmachine").output().expect("cc");
    assert!(triple.status.success());
    let triple = String::from_utf8(triple.stdout).expect("compiler triple");
    let status = Command::new(env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into()))
        .args([
            "-target", "bpf", "-mcpu=v3", "-O2", "-g", "-Wall", "-Werror",
        ])
        .arg(format!("-I/usr/include/{}", triple.trim()))
        .args(["-c", "bpf/observe.bpf.c", "-o"])
        .arg(out.join("observe.bpf.o"))
        .status()
        .expect("run clang");
    assert!(status.success(), "BPF compilation failed");
}
