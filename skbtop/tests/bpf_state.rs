use std::{env, fs, path::PathBuf, process::Command};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn production_bpf_state_machine() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scratch = Scratch(env::temp_dir().join(format!(
        "skbtop-bpf-state-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    )));
    fs::create_dir(&scratch.0).expect("create native harness directory");
    let binary = scratch.0.join("bpf_state");
    let compiler = env::var_os("SKBTOP_TEST_CC").unwrap_or_else(|| "cc".into());
    let output = Command::new(&compiler)
        .current_dir(&root)
        .args([
            "-std=gnu11",
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DSKBTOP_UNIT_TEST",
            "tests/bpf_state.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .unwrap_or_else(|err| panic!("run native compiler {compiler:?}: {err}"));
    assert!(
        output.status.success(),
        "native harness compilation failed ({compiler:?}):\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary)
        .output()
        .expect("run production BPF harness");
    assert!(
        output.status.success(),
        "production BPF harness failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
