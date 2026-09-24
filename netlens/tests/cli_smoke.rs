use std::process::Command;

fn netlens() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netlens"))
}

#[test]
fn help_exposes_only_the_default_monitor_options() {
    let output = netlens().arg("--help").output().unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("Usage: netlens [OPTIONS] [COMMAND]"));
    for option in ["--interval", "--interface"] {
        assert!(help.contains(option), "missing {option} from help");
    }
    for removed in [
        "doctor",
        "report",
        "replay",
        "--ifindex",
        "--section",
        "compinit",
        "compdef",
    ] {
        assert!(
            !help.contains(removed),
            "removed surface {removed:?} leaked"
        );
    }
}

#[test]
fn module_commands_are_accepted_before_the_tty_boundary() {
    for command in [
        "overview",
        "interface",
        "qdisc",
        "softirq",
        "hardirq",
        "socket",
        "transport",
        "network",
        "conntrack",
        "route",
        "providers",
    ] {
        let output = netlens()
            .args([command, "--interval", "1s"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{command}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal required"));
    }
}

#[test]
fn completion_command_generates_shell_script_without_a_tty() {
    let output = netlens().args(["completions", "bash"]).output().unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let completion = String::from_utf8(output.stdout).unwrap();
    assert!(completion.contains("hardirq"));
    assert!(completion.contains("--interval"));
    assert!(!completion.contains("--ifindex"));
    assert!(!completion.contains("--section"));
}

#[test]
fn removed_subcommands_are_rejected_by_clap() {
    for command in ["doctor", "report", "replay"] {
        let output = netlens().arg(command).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{command}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    }
}

#[test]
fn monitor_arguments_fail_closed() {
    for arguments in [
        vec!["--interval", "249ms"],
        vec!["--interval", "61s"],
        vec!["--section", "transport"],
        vec!["--interface", "../eth0"],
        vec!["--interface", "eth\u{1b}[2J"],
        vec!["--interface", "eth\u{7}0"],
        vec!["--ifindex", "0"],
        vec!["--interface", "eth0", "--ifindex", "2"],
    ] {
        let output = netlens().args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!output.stderr.contains(&0x1b));
        assert!(!output.stderr.contains(&0x07));
    }
}

#[test]
fn non_tty_start_fails_without_writing_ansi() {
    let output = netlens().output().unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!output.stdout.contains(&0x1b));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("interactive terminal required"));
    assert!(!stderr.contains('\u{1b}'));
}

#[test]
fn removed_options_are_rejected_before_the_tty_boundary() {
    for arguments in [["--section", "socket"], ["--ifindex", "2"]] {
        let output = netlens().args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
    }
}
