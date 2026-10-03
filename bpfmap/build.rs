fn main() {
    cc::Build::new()
        .file("src/btf_format.c")
        .warnings(true)
        .compile("bpfmap_btf");
    println!("cargo:rerun-if-changed=src/btf_format.c");
}
