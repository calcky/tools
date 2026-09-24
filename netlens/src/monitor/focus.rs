use super::MonitorSection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectionFocus {
    Section(MonitorSection),
    Transport,
    Network,
    Route,
    ConntrackFlows,
    InterfaceDetail,
    InterfaceLayer(MonitorSection),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Group {
    Protocols,
    Sockets,
    Conntrack,
    Rules,
    Softnet,
    Softirq,
    Hardirq,
    Tc,
    Links,
    Nic,
    Configuration,
}

impl From<MonitorSection> for CollectionFocus {
    fn from(section: MonitorSection) -> Self {
        Self::Section(section)
    }
}

impl CollectionFocus {
    pub(crate) fn allows_provider(self, provider: &str) -> bool {
        use Group::*;
        let group = match provider {
            "linux.proc.net.snmp" | "linux.proc.net.netstat" | "linux.proc.net.snmp6" => Protocols,
            "linux.proc.net.sockstat" | "linux.proc.net.sockstat6" => Sockets,
            "linux.proc.netfilter.conntrack" => Conntrack,
            "linux.nft.ruleset" | "linux.iptables.ipv4" | "linux.iptables.ipv6" => Rules,
            "linux.proc.net.softnet_stat" => Softnet,
            "linux.proc.softirqs" => Softirq,
            "linux.proc.interrupts" => Hardirq,
            "linux.tc.json" | "linux.rtnetlink.tc" => Tc,
            "linux.rtnetlink.link_stats" | "linux.sysfs.net.statistics" | "linux.proc.net.dev" => {
                Links
            }
            "linux.sysfs.net.nic" | "linux.ethtool.text" | "linux.ethtool.link_text" => Nic,
            "linux.proc.sys.net.ipv4" | "linux.proc.sys.net.core" => Configuration,
            _ => return self.all(),
        };
        self.needs(group)
    }

    pub(crate) fn needs(self, group: Group) -> bool {
        use Group::*;
        use MonitorSection as S;
        match self {
            Self::Section(S::Overview | S::Providers) => true,
            Self::Section(S::Socket) => matches!(group, Protocols | Sockets | Configuration),
            Self::Section(S::Netfilter) => matches!(group, Conntrack | Rules),
            Self::Section(S::Tc) => group == Tc,
            Self::Section(S::Nic) => matches!(group, Links | Nic),
            Self::Section(S::Netdevice) => matches!(group, Links | Softnet | Configuration),
            Self::Section(S::Softirq) => matches!(group, Softnet | Softirq | Configuration),
            Self::Section(S::Hardirq) => group == Hardirq,
            Self::Transport | Self::Network | Self::Route => group == Protocols,
            Self::ConntrackFlows => group == Conntrack,
            Self::InterfaceDetail => matches!(
                group,
                Links | Nic | Tc | Hardirq | Softnet | Softirq | Configuration
            ),
            Self::InterfaceLayer(section) => {
                matches!(group, Links | Nic) || Self::Section(section).needs(group)
            }
        }
    }

    pub(crate) fn foreground(self, group: Group) -> bool {
        use MonitorSection as S;
        if let Self::InterfaceLayer(section) = self {
            return Self::Section(section).foreground(group);
        }
        matches!(
            (self, group),
            (Self::Section(S::Nic), Group::Nic)
                | (Self::Section(S::Hardirq), Group::Hardirq)
                | (Self::Section(S::Netfilter), Group::Rules)
                | (Self::Section(S::Overview | S::Providers | S::Tc), Group::Tc)
                | (
                    Self::InterfaceDetail,
                    Group::Nic | Group::Tc | Group::Hardirq
                )
        )
    }

    pub(crate) fn all(self) -> bool {
        matches!(
            self,
            Self::Section(MonitorSection::Overview | MonitorSection::Providers)
        )
    }
}
