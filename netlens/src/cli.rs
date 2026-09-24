use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

use crate::monitor::{
    CollectionSection, InitialPage, InterfaceViewAnchor, MonitorPlan, MonitorSection,
    MonitorValidationError, SamplingInterval,
};

const COMPLETION_HELP: &str = "Shell completion (load in your current shell; no sudo needed):
  Zsh:   source <(netlens completions zsh)
  Bash:  source <(netlens completions bash)
  Fish:  netlens completions fish | source";

#[derive(Debug, Args)]
struct MonitorArgs {
    /// Sampling interval in seconds (0.25-60)
    #[arg(short = 'd', alias = "interval", value_name = "SECONDS", value_parser = parse_interval, default_value = "1", global = true)]
    interval: SamplingInterval,
    /// Show rows for these Linux interfaces (comma-separated)
    #[arg(short = 'i', alias = "interface", value_name = "INTERFACES", value_delimiter = ',', value_parser = parse_interface, global = true)]
    interface: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum ModuleCommand {
    /// Show the complete overview
    Overview,
    /// Show network interfaces and NIC configuration
    #[command(alias = "netdev")]
    Interface,
    /// Show qdisc and traffic-control statistics
    #[command(alias = "tc")]
    Qdisc,
    /// Show per-CPU softirq statistics
    Softirq,
    /// Show network hardware IRQ statistics
    Hardirq,
    /// Show socket tables
    Socket,
    /// Show TCP/UDP transport metrics
    Transport,
    /// Show IP and ICMP network metrics
    Network,
    /// Show conntrack flows
    #[command(alias = "netfilter")]
    Conntrack,
    /// Show routes, rules and neighbours
    #[command(alias = "routes")]
    Route,
    /// Show collection provider health
    Providers,
    /// Generate shell completion scripts
    #[command(after_help = COMPLETION_HELP)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl ModuleCommand {
    const fn page(self) -> Option<InitialPage> {
        match self {
            Self::Overview => Some(InitialPage::Overview),
            Self::Interface => Some(InitialPage::Interface),
            Self::Qdisc => Some(InitialPage::Qdisc),
            Self::Softirq => Some(InitialPage::Softirq),
            Self::Hardirq => Some(InitialPage::Hardirq),
            Self::Socket => Some(InitialPage::Socket),
            Self::Transport => Some(InitialPage::Transport),
            Self::Network => Some(InitialPage::Network),
            Self::Conntrack => Some(InitialPage::Conntrack),
            Self::Route => Some(InitialPage::Route),
            Self::Providers => Some(InitialPage::Providers),
            Self::Completions { .. } => None,
        }
    }

    fn completion_shell(&self) -> Option<Shell> {
        match self {
            Self::Completions { shell } => Some(*shell),
            _ => None,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "netlens",
    version,
    about = "Monitor Linux network health by layer",
    after_help = COMPLETION_HELP
)]
pub struct Cli {
    #[command(flatten)]
    args: MonitorArgs,
    #[command(subcommand)]
    command: Option<ModuleCommand>,
}

impl Cli {
    pub fn completion_shell(&self) -> Option<Shell> {
        self.command
            .as_ref()
            .and_then(ModuleCommand::completion_shell)
    }

    pub fn into_monitor_plan(self) -> Result<MonitorPlan, MonitorValidationError> {
        let interface_anchor = if self.args.interface.is_empty() {
            None
        } else {
            Some(InterfaceViewAnchor::named_many(self.args.interface)?)
        };

        let command_page = self.command.and_then(ModuleCommand::page);
        let section = command_page.map_or(MonitorSection::Overview, InitialPage::monitor_section);
        let plan = MonitorPlan::from_parts(
            self.args.interval,
            section,
            CollectionSection::ALL,
            interface_anchor,
        )?;
        Ok(command_page.map_or(plan.clone(), |page| plan.with_initial_page(page)))
    }
}

fn parse_interval(value: &str) -> Result<SamplingInterval, MonitorValidationError> {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        format!("{value}s").parse()
    } else {
        value.parse()
    }
}

fn parse_interface(value: &str) -> Result<String, String> {
    InterfaceViewAnchor::named(value)
        .map(|_| value.to_owned())
        .map_err(|_| format!("invalid Linux interface name {value:?}"))
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    #[test]
    fn defaults_to_one_second_overview_with_all_collection_sections() {
        let plan = Cli::try_parse_from(["netlens"])
            .unwrap()
            .into_monitor_plan()
            .unwrap();

        assert_eq!(plan.interval().as_millis(), 1_000);
        assert_eq!(plan.initial_section(), MonitorSection::Overview);
        assert_eq!(
            plan.enabled_sections(),
            &CollectionSection::ALL.into_iter().collect()
        );
        assert_eq!(plan.interface_anchor(), None);
    }

    #[test]
    fn accepts_interface_name_anchor() {
        let named = Cli::try_parse_from(["netlens", "-i", "eth0"])
            .unwrap()
            .into_monitor_plan()
            .unwrap();
        assert_eq!(
            named.interface_anchor(),
            Some(&InterfaceViewAnchor::named("eth0").unwrap())
        );
    }

    #[test]
    fn short_options_accept_multiple_interfaces_before_or_after_modules() {
        let expected = InterfaceViewAnchor::named_many(["eth0".into(), "eth1".into()]).unwrap();
        for args in [
            vec!["netlens", "-d", "0.5", "-i", "eth1,eth0,eth1", "interface"],
            vec!["netlens", "interface", "-d", "0.5", "-i", "eth0,eth1"],
            vec![
                "netlens",
                "interface",
                "--interval",
                "500ms",
                "--interface",
                "eth0,eth1",
            ],
            vec![
                "netlens",
                "interface",
                "-d",
                "0.5",
                "-i",
                "eth0",
                "-i",
                "eth1",
            ],
        ] {
            let plan = Cli::try_parse_from(args)
                .unwrap()
                .into_monitor_plan()
                .unwrap();
            assert_eq!(plan.interval().as_millis(), 500);
            assert_eq!(plan.initial_page(), Some(InitialPage::Interface));
            assert_eq!(plan.interface_anchor(), Some(&expected));
        }
    }

    #[test]
    fn interval_numbers_are_seconds_with_millisecond_precision() {
        for (value, millis) in [
            ("1", 1000),
            ("2", 2000),
            ("0.25", 250),
            ("0.5", 500),
            ("1.001", 1001),
            ("60", 60_000),
        ] {
            let plan = Cli::try_parse_from(["netlens", "-d", value])
                .unwrap()
                .into_monitor_plan()
                .unwrap();
            assert_eq!(plan.interval().as_millis(), millis, "{value}");
        }
        for value in ["0", "0.249", "60.001", "0.2501", "NaN", "inf", "", "1..5"] {
            assert!(
                Cli::try_parse_from(["netlens", "-d", value]).is_err(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn interface_lists_reject_empty_or_invalid_members() {
        for value in [
            "",
            ",",
            "eth0,",
            ",eth0",
            "eth0,,eth1",
            "eth0,../eth1",
            "eth0, eth1",
        ] {
            let error = Cli::try_parse_from(["netlens", "-i", value]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{value:?}");
        }
    }

    #[test]
    fn rejects_removed_options() {
        for arguments in [["--section", "socket"], ["--ifindex", "2"]] {
            let error = Cli::try_parse_from(["netlens", arguments[0], arguments[1]]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn old_subcommands_are_unknown_arguments() {
        for old_command in ["report", "doctor", "replay"] {
            let error = Cli::try_parse_from(["netlens", old_command]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand, "{old_command}");
        }
    }

    #[test]
    fn module_commands_select_the_matching_initial_page_and_allow_global_options_afterward() {
        let hardirq = Cli::try_parse_from(["netlens", "hardirq", "--interval", "2s"])
            .unwrap()
            .into_monitor_plan()
            .unwrap();
        assert_eq!(hardirq.initial_page(), Some(InitialPage::Hardirq));
        assert_eq!(hardirq.initial_section(), MonitorSection::Hardirq);
        assert_eq!(hardirq.interval().as_millis(), 2_000);

        let route = Cli::try_parse_from(["netlens", "route"])
            .unwrap()
            .into_monitor_plan()
            .unwrap();
        assert_eq!(route.initial_page(), Some(InitialPage::Route));
        assert_eq!(route.initial_section(), MonitorSection::Overview);

        let alias = Cli::try_parse_from(["netlens", "qdisc"])
            .unwrap()
            .into_monitor_plan()
            .unwrap();
        assert_eq!(alias.initial_page(), Some(InitialPage::Qdisc));
        assert_eq!(alias.initial_section(), MonitorSection::Tc);
    }
}
