fn main() {
    let mut build = cc::Build::new();
    build.file("src/btf_format.c").warnings(true);
    if let Ok(include) = std::env::var("BPFMAP_INCLUDE_DIR") {
        build.include(include);
    }
    build.compile("bpfmap_btf");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        println!("cargo:rustc-link-lib=static=argp");
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-lzstd");
    }
    println!("cargo:rerun-if-changed=src/btf_format.c");
    println!("cargo:rerun-if-changed=Cross.toml");
    println!("cargo:rerun-if-changed=ci/Dockerfile.x86_64");
    println!("cargo:rerun-if-changed=ci/Dockerfile.arm64");
    println!("cargo:rerun-if-changed=ci/Dockerfile.arm");
    println!("cargo:rerun-if-env-changed=BPFMAP_INCLUDE_DIR");
}
