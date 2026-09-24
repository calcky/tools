use std::io;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use clap_complete::generate;
use netlens::cli::Cli;
use netlens::collect::SystemPaths;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(shell) = cli.completion_shell() {
        let mut command = Cli::command();
        generate(shell, &mut command, "netlens", &mut io::stdout());
        return ExitCode::SUCCESS;
    }
    let plan = match cli.into_monitor_plan() {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("netlens: {error}");
            return ExitCode::from(2);
        }
    };
    match netlens::tui::run(plan, SystemPaths::default()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("netlens: {error:#}");
            ExitCode::from(3)
        }
    }
}
