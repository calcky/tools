use std::{env, path::PathBuf, process::Command};

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let bpf_arch = match arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        _ => panic!("fdtop currently requires native x86_64 or arm64"),
    };
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        println!("cargo:rustc-link-lib=static=argp");
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-lzstd");
    } else {
        println!("cargo:rustc-link-lib=static=zstd");
    }
    println!("cargo:rerun-if-changed=bpf/observe.bpf.c");
    println!("cargo:rerun-if-changed=bpf/events.bpf.c");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=FDTOP_BPF_DIR");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let triple = Command::new("cc").arg("-dumpmachine").output().expect("cc");
    assert!(triple.status.success());
    let triple = String::from_utf8(triple.stdout).unwrap();
    for (name, latency) in [
        ("observe-light.bpf.o", 0),
        ("observe.bpf.o", 1),
        ("events.bpf.o", 0),
    ] {
        if let Some(directory) = env::var_os("FDTOP_BPF_DIR") {
            let source = PathBuf::from(directory).join(name);
            println!("cargo:rerun-if-changed={}", source.display());
            std::fs::copy(source, out.join(name)).expect("copy precompiled BPF object");
            continue;
        }
        let status = Command::new(env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into()))
            .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
            .arg(format!("-D__TARGET_ARCH_{bpf_arch}"))
            .arg(format!("-DFDTOP_LATENCY={latency}"))
            .arg(format!("-I/usr/include/{}", triple.trim()))
            .args([
                "-c",
                if name == "events.bpf.o" {
                    "bpf/events.bpf.c"
                } else {
                    "bpf/observe.bpf.c"
                },
                "-o",
            ])
            .arg(out.join(name))
            .status()
            .expect("run clang");
        assert!(status.success(), "BPF compilation failed");
    }
}
