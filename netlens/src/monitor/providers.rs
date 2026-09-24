use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Write as _};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crate::collect::{irq, netfilter, nic, procfs, rtnetlink, sysfs, tc, SystemPaths};
use crate::model::{MetricKey, MetricSample};

use super::catalog::{metric_catalog, MetricDescriptor};
use super::focus::{CollectionFocus, Group};
use super::model::{
    CounterBits, MetricId, MetricKind, MetricLabel, MetricLabels, MetricReading, MonitorError,
    MonitorErrorCode, MonitorSection, MonitorValidationError, ProviderHealth, ProviderId,
    ProviderSample, SampleReading, StateValue, UnavailableReason, MAX_READINGS_PER_PROVIDER,
};

const PROC_SNMP: &str = "linux.proc.net.snmp";
const PROC_NETSTAT: &str = "linux.proc.net.netstat";
const PROC_SNMP6: &str = "linux.proc.net.snmp6";
const PROC_SOCKSTAT: &str = "linux.proc.net.sockstat";
const PROC_SOCKSTAT6: &str = "linux.proc.net.sockstat6";
const PROC_CONNTRACK: &str = "linux.proc.netfilter.conntrack";
const NFT_RULESET: &str = "linux.nft.ruleset";
const IPTABLES_IPV4: &str = "linux.iptables.ipv4";
const IPTABLES_IPV6: &str = "linux.iptables.ipv6";
const PROC_SOFTNET: &str = "linux.proc.net.softnet_stat";
const PROC_SYS_NET_CORE: &str = "linux.proc.sys.net.core";
const PROC_SYS_NET_IPV4: &str = "linux.proc.sys.net.ipv4";
const PROC_SOFTIRQS: &str = "linux.proc.softirqs";
const PROC_INTERRUPTS: &str = "linux.proc.interrupts";
const TC_JSON: &str = "linux.tc.json";
const TC_NETLINK: &str = "linux.rtnetlink.tc";
const RTNETLINK_LINK: &str = "linux.rtnetlink.link_stats";
const SYSFS_LINK: &str = "linux.sysfs.net.statistics";
const PROC_NET_DEV: &str = "linux.proc.net.dev";
const SYSFS_NIC: &str = "linux.sysfs.net.nic";
const ETHTOOL_TEXT: &str = "linux.ethtool.text";
const ETHTOOL_LINK_TEXT: &str = "linux.ethtool.link_text";
const NIC_SETTINGS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const CONFIG_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const RULES_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const DEVICE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const QDISC_METRICS_PER_ROW: usize = 13;
const MAX_QDISC_ROW_IDS: usize = super::model::MAX_ADMITTED_SERIES / QDISC_METRICS_PER_ROW;
const NETFILTER_METRICS_PER_RULE: usize = 4;
const NETFILTER_METRICS_PER_CHAIN: usize = 3;
const MAX_NETFILTER_RULE_ROW_IDS: usize =
    super::model::MAX_ADMITTED_SERIES / NETFILTER_METRICS_PER_RULE;

const IMPLEMENTED_PROVIDERS: [&str; 22] = [
    PROC_SNMP,
    PROC_NETSTAT,
    PROC_SNMP6,
    PROC_SOCKSTAT,
    PROC_SOCKSTAT6,
    PROC_CONNTRACK,
    NFT_RULESET,
    IPTABLES_IPV4,
    IPTABLES_IPV6,
    PROC_SOFTNET,
    PROC_SYS_NET_CORE,
    PROC_SYS_NET_IPV4,
    PROC_SOFTIRQS,
    PROC_INTERRUPTS,
    TC_JSON,
    TC_NETLINK,
    RTNETLINK_LINK,
    SYSFS_LINK,
    PROC_NET_DEV,
    SYSFS_NIC,
    ETHTOOL_TEXT,
    ETHTOOL_LINK_TEXT,
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NetfilterRuleIdentity {
    backend: String,
    family: String,
    table: String,
    chain: String,
    handle: Option<u64>,
    fingerprint: netfilter::RuleFingerprint,
    duplicate_ordinal: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NicCollectionTiming {
    finished_at: Duration,
    collection_duration: Duration,
}

impl NicCollectionTiming {
    fn observed(session_start: Instant, started: Instant, finished: Instant) -> Self {
        let finished_at = finished.saturating_duration_since(session_start);
        Self {
            finished_at,
            collection_duration: finished.saturating_duration_since(started).min(finished_at),
        }
    }
}

mod nic_configuration;

#[derive(Debug, Default)]
struct NicSettingsCache {
    timing: Option<NicCollectionTiming>,
    interfaces: BTreeMap<String, (u32, bool)>,
    sample: Option<ProviderSample>,
}

impl NicSettingsCache {
    fn refresh_due(&self, now: Duration) -> bool {
        self.timing.is_none_or(|timing| {
            now.saturating_sub(timing.finished_at) >= NIC_SETTINGS_REFRESH_INTERVAL
        })
    }

    fn record(&mut self, collection: &nic::NicCollection, timing: NicCollectionTiming) {
        self.interfaces = collection
            .interfaces
            .iter()
            .map(|interface| {
                (
                    interface.interface.clone(),
                    (interface.ifindex, interface.hardware_backed),
                )
            })
            .collect();
        self.sample = Some(translate_nic_settings(collection, timing));
        self.timing = Some(timing);
    }

    fn matches_inventory(&self, collection: &nic::NicCollection) -> bool {
        let mut interfaces = 0;
        for interface in &collection.interfaces {
            if self.interfaces.get(interface.interface.as_str())
                != Some(&(interface.ifindex, interface.hardware_backed))
            {
                return false;
            }
            interfaces += 1;
        }
        // A removed interface also invalidates the aggregate readings and health.
        self.sample.is_some() && interfaces == self.interfaces.len()
    }

    #[cfg(test)]
    fn collect_samples(
        &mut self,
        now: Duration,
        readings: &mut NicReadingsCache,
        mut collect: impl FnMut(bool) -> (nic::NicCollection, NicCollectionTiming),
    ) -> Vec<ProviderSample> {
        let refresh_settings = self.refresh_due(now);
        let (mut collection, mut current_timing) = collect(refresh_settings);
        if refresh_settings {
            self.record(&collection, current_timing);
        } else if !self.matches_inventory(&collection) {
            // Refresh the complete inventory so every settings row has one real timestamp.
            (collection, current_timing) = collect(true);
            self.record(&collection, current_timing);
        }

        let settings_sample = if self.interfaces.is_empty() {
            // No settings probe ran; report the current inventory observation at zero cost.
            translate_nic_settings(&collection, current_timing)
        } else {
            self.sample
                .as_ref()
                .expect("settings were collected")
                .clone()
        };
        translate_nic_collection(&collection, current_timing, settings_sample, readings)
    }
}

#[derive(Debug, Default)]
struct CachedSamples {
    collected_at: Option<Duration>,
    samples: Vec<ProviderSample>,
}

impl CachedSamples {
    fn refresh_due(&self, now: Duration, foreground: bool, background_interval: Duration) -> bool {
        foreground
            || self
                .collected_at
                .is_none_or(|at| now.saturating_sub(at) >= background_interval)
    }

    fn record(&mut self, at: Duration, samples: Vec<ProviderSample>) {
        self.collected_at = Some(at);
        self.samples = samples;
    }
}

#[derive(Debug)]
pub(crate) struct BuiltinCollector {
    paths: SystemPaths,
    qdisc_row_ids: BTreeMap<tc::QdiscIdentity, u64>,
    next_qdisc_row_id: u64,
    netfilter_rule_row_ids: BTreeMap<NetfilterRuleIdentity, u64>,
    next_netfilter_rule_row_id: u64,
    nic_collector: nic::NicCollector,
    nic_settings: NicSettingsCache,
    nic_configuration: nic_configuration::Service,
    nic_readings: NicReadingsCache,
    rtnetlink: rtnetlink::Context,
    link_readings: LinkReadingsCache,
    metric_readings: BTreeMap<&'static str, MetricReadingsCache>,
    softnet: procfs::SoftnetContext,
    focus: CollectionFocus,
    netfilter_cache: CachedSamples,
    tc_cache: CachedSamples,
    tc_native: tc::QdiscCollector,
    nic_cache: CachedSamples,
    hardirq_cache: CachedSamples,
    hardirq_collector: irq::HardirqCollector,
    hardirq_snapshot: Option<std::sync::Arc<super::hardirq::HardirqSnapshot>>,
    config_cache: CachedSamples,
}

impl BuiltinCollector {
    pub(crate) fn new(paths: SystemPaths) -> Self {
        Self {
            paths,
            qdisc_row_ids: BTreeMap::new(),
            next_qdisc_row_id: 1,
            netfilter_rule_row_ids: BTreeMap::new(),
            next_netfilter_rule_row_id: 1,
            nic_collector: nic::NicCollector::default(),
            nic_settings: NicSettingsCache::default(),
            nic_configuration: nic_configuration::Service::default(),
            nic_readings: NicReadingsCache::default(),
            rtnetlink: rtnetlink::Context::default(),
            link_readings: LinkReadingsCache::default(),
            metric_readings: BTreeMap::new(),
            softnet: procfs::SoftnetContext::default(),
            focus: MonitorSection::Overview.into(),
            netfilter_cache: CachedSamples::default(),
            tc_cache: CachedSamples::default(),
            tc_native: tc::QdiscCollector::default(),
            nic_cache: CachedSamples::default(),
            hardirq_cache: CachedSamples::default(),
            hardirq_collector: irq::HardirqCollector::default(),
            hardirq_snapshot: None,
            config_cache: CachedSamples::default(),
        }
    }

    pub(crate) fn collect(&mut self, session_start: Instant) -> Vec<ProviderSample> {
        let mut samples = Vec::new();

        if self.focus.needs(Group::Configuration) {
            if self.config_cache.refresh_due(
                session_start.elapsed(),
                false,
                CONFIG_REFRESH_INTERVAL,
            ) {
                let configuration = vec![
                    collect_attempt(
                        session_start,
                        PROC_SYS_NET_IPV4,
                        &mut self.metric_readings,
                        || {
                            procfs::collect_tcp_memory_limit(&self.paths.proc_root)
                                .map_err(AttemptError::proc)
                        },
                    ),
                    collect_attempt(
                        session_start,
                        PROC_SYS_NET_CORE,
                        &mut self.metric_readings,
                        || {
                            procfs::collect_net_core_settings(&self.paths.proc_root)
                                .map_err(AttemptError::proc)
                        },
                    ),
                ];
                self.config_cache
                    .record(session_start.elapsed(), configuration);
            }
            samples.extend(self.config_cache.samples.iter().cloned());
        }

        if self.focus.needs(Group::Protocols) {
            samples.push(collect_attempt(
                session_start,
                PROC_SNMP,
                &mut self.metric_readings,
                || {
                    procfs::collect_named_tables(
                        &self.paths.proc_root.join("net/snmp"),
                        "proc_net_snmp",
                    )
                    .map_err(AttemptError::proc)
                },
            ));
            samples.push(collect_attempt(
                session_start,
                PROC_NETSTAT,
                &mut self.metric_readings,
                || {
                    procfs::collect_named_tables(
                        &self.paths.proc_root.join("net/netstat"),
                        "proc_net_netstat",
                    )
                    .map_err(AttemptError::proc)
                },
            ));
            samples.push(collect_attempt(
                session_start,
                PROC_SNMP6,
                &mut self.metric_readings,
                || {
                    procfs::collect_name_values(
                        &self.paths.proc_root.join("net/snmp6"),
                        "proc_net_snmp6",
                    )
                    .map_err(AttemptError::proc)
                },
            ));
        }
        if self.focus.needs(Group::Sockets) {
            samples.push(collect_attempt(
                session_start,
                PROC_SOCKSTAT,
                &mut self.metric_readings,
                || {
                    procfs::collect_sockstat(
                        &self.paths.proc_root.join("net/sockstat"),
                        "proc_sockstat",
                    )
                    .map_err(AttemptError::proc)
                },
            ));
            samples.push(collect_attempt(
                session_start,
                PROC_SOCKSTAT6,
                &mut self.metric_readings,
                || {
                    procfs::collect_sockstat(
                        &self.paths.proc_root.join("net/sockstat6"),
                        "proc_sockstat6",
                    )
                    .map_err(AttemptError::proc)
                },
            ));
        }
        if self.focus.needs(Group::Conntrack) {
            samples.push(collect_attempt(
                session_start,
                PROC_CONNTRACK,
                &mut self.metric_readings,
                || {
                    procfs::collect_conntrack(&self.paths.proc_root, &self.paths.sys_root)
                        .map_err(AttemptError::proc)
                },
            ));
        }
        if self.focus.needs(Group::Rules) {
            if self.netfilter_cache.refresh_due(
                session_start.elapsed(),
                self.focus.foreground(Group::Rules),
                RULES_REFRESH_INTERVAL,
            ) {
                let rules = vec![
                    self.collect_netfilter_sample(
                        session_start,
                        NFT_RULESET,
                        netfilter::collect_nftables,
                    ),
                    self.collect_netfilter_sample(
                        session_start,
                        IPTABLES_IPV4,
                        netfilter::collect_iptables_ipv4,
                    ),
                    self.collect_netfilter_sample(
                        session_start,
                        IPTABLES_IPV6,
                        netfilter::collect_iptables_ipv6,
                    ),
                ];
                self.netfilter_cache.record(session_start.elapsed(), rules);
            }
            samples.extend(self.netfilter_cache.samples.iter().cloned());
        }
        if self.focus.needs(Group::Softnet) {
            samples.push(collect_attempt(
                session_start,
                PROC_SOFTNET,
                &mut self.metric_readings,
                || {
                    self.softnet
                        .collect(
                            &self.paths.proc_root.join("net/softnet_stat"),
                            &self.paths.sys_root.join("devices/system/cpu/online"),
                        )
                        .map_err(AttemptError::proc)
                },
            ));
        }
        if self.focus.needs(Group::Softirq) {
            samples.push(collect_attempt(
                session_start,
                PROC_SOFTIRQS,
                &mut self.metric_readings,
                || {
                    irq::collect_softirqs(&self.paths.proc_root.join("softirqs"))
                        .map_err(AttemptError::irq)
                },
            ));
        }
        if self.focus.needs(Group::Hardirq) {
            if self.hardirq_cache.refresh_due(
                session_start.elapsed(),
                self.focus.foreground(Group::Hardirq),
                DEVICE_REFRESH_INTERVAL,
            ) {
                let sample = collect_hardirq_with_table(
                    session_start,
                    &self.paths,
                    &mut self.hardirq_collector,
                    &mut self.hardirq_snapshot,
                );
                self.hardirq_cache
                    .record(session_start.elapsed(), vec![sample]);
            }
            samples.extend(self.hardirq_cache.samples.iter().cloned());
        }
        if self.focus.needs(Group::Tc) {
            if self.tc_cache.refresh_due(
                session_start.elapsed(),
                self.focus.foreground(Group::Tc),
                RULES_REFRESH_INTERVAL,
            ) {
                let samples = self.collect_tc_samples(session_start);
                self.tc_cache.record(session_start.elapsed(), samples);
            }
            samples.extend(self.tc_cache.samples.iter().cloned());
        }

        if self.focus.needs(Group::Links) {
            let share_nic_metadata = self.paths.sys_root == std::path::Path::new("/sys")
                && self.focus.needs(Group::Nic)
                && self.nic_cache.refresh_due(
                    session_start.elapsed(),
                    self.focus.foreground(Group::Nic),
                    DEVICE_REFRESH_INTERVAL,
                );
            let (rtnetlink, metadata) = collect_rtnetlink_sample(
                session_start,
                &mut self.rtnetlink,
                &mut self.link_readings,
                share_nic_metadata,
            );
            let use_link_fallback =
                !rtnetlink.health().is_fresh() || rtnetlink.readings().is_empty();
            samples.push(rtnetlink);

            if use_link_fallback {
                let sysfs =
                    collect_attempt(session_start, SYSFS_LINK, &mut self.metric_readings, || {
                        sysfs::collect_link_stats(&self.paths.sys_root, None)
                            .map_err(AttemptError::sysfs)
                    });
                let use_proc_fallback = !sysfs.health().is_fresh() || sysfs.readings().is_empty();
                samples.push(sysfs);

                if use_proc_fallback {
                    samples.push(collect_attempt(
                        session_start,
                        PROC_NET_DEV,
                        &mut self.metric_readings,
                        || {
                            let mut metrics = procfs::collect_net_dev(
                                &self.paths.proc_root.join("net/dev"),
                                None,
                            )
                            .map_err(AttemptError::proc_net_dev)?;
                            sysfs::attach_interface_ifindices(&self.paths.sys_root, &mut metrics)
                                .map_err(AttemptError::sysfs)?;
                            Ok(metrics)
                        },
                    ));
                }
            }

            // Keep this scheduling check after link collection: if the deadline
            // passed during it, collect independently instead of delaying a poll.
            if self.focus.needs(Group::Nic)
                && self.nic_cache.refresh_due(
                    session_start.elapsed(),
                    self.focus.foreground(Group::Nic),
                    DEVICE_REFRESH_INTERVAL,
                )
            {
                let nic_samples = self.collect_nic_samples(session_start, metadata);
                self.nic_cache.record(session_start.elapsed(), nic_samples);
            }
            if self.focus.needs(Group::Nic) {
                self.poll_nic_configuration(session_start);
                samples.extend(self.nic_cache.samples.iter().cloned());
            }
        }

        if self.focus.all() {
            add_unsupported_samples(&mut samples, session_start);
        }
        samples.sort_by(|left, right| left.provider().cmp(right.provider()));
        samples
    }

    fn collect_nic_samples(
        &mut self,
        session_start: Instant,
        metadata: Option<rtnetlink::FreshLinkMetadata>,
    ) -> Vec<ProviderSample> {
        let started = Instant::now();
        let (collection, metadata_started) =
            self.nic_collector
                .collect_with_metadata(&self.paths.sys_root, false, metadata);
        let timing = NicCollectionTiming::observed(
            session_start,
            metadata_started.unwrap_or(started),
            Instant::now(),
        );
        self.nic_configuration
            .observe_inventory(self.nic_collector.configuration_inventory());
        self.poll_nic_configuration(session_start);
        let current =
            self.nic_configuration.current() && self.nic_settings.matches_inventory(&collection);
        let mut request_failure = None;
        if !current
            || self
                .nic_settings
                .refresh_due(session_start.elapsed() + nic_configuration::STAGGER)
        {
            let stagger = if current {
                nic_configuration::STAGGER
            } else {
                Duration::ZERO
            };
            if let Err(error) = self.nic_configuration.request(
                &self.paths.sys_root,
                &collection,
                session_start,
                stagger,
            ) {
                request_failure = Some(error_sample(
                    ETHTOOL_LINK_TEXT,
                    session_start.elapsed(),
                    Duration::ZERO,
                    MonitorErrorCode::Io,
                    error.to_string(),
                ));
            }
        }
        let settings = request_failure
            .or_else(|| {
                if current {
                    self.nic_settings.sample.clone()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| translate_nic_settings(&collection, timing));
        translate_nic_collection(&collection, timing, settings, &mut self.nic_readings)
    }

    fn poll_nic_configuration(&mut self, session_start: Instant) {
        let replacement = match self.nic_configuration.poll() {
            Ok(Some(batch)) => {
                self.nic_settings.record(&batch.collection, batch.timing);
                self.nic_settings.sample.clone()
            }
            Ok(None) => None,
            Err(error) => Some(error_sample(
                ETHTOOL_LINK_TEXT,
                session_start.elapsed(),
                Duration::ZERO,
                MonitorErrorCode::Io,
                error.to_string(),
            )),
        };
        if let Some(sample) = replacement {
            if let Some(slot) = self
                .nic_cache
                .samples
                .iter_mut()
                .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            {
                *slot = sample;
            }
        }
    }

    fn collect_tc_samples(&mut self, session_start: Instant) -> Vec<ProviderSample> {
        let started = Instant::now();
        let native = self.tc_native.collect(&self.paths.sys_root, None);
        let sys_root = self.paths.sys_root.clone();
        self.finish_tc_collection(session_start, started, native, || {
            tc::collect_qdiscs(&sys_root, None)
        })
    }

    fn finish_tc_collection(
        &mut self,
        session_start: Instant,
        started: Instant,
        native: Result<Vec<tc::QdiscRow>, tc::CollectError>,
        fallback: impl FnOnce() -> Result<Vec<tc::QdiscRow>, tc::CollectError>,
    ) -> Vec<ProviderSample> {
        let native_succeeded = native.is_ok();
        let native = self.tc_result_sample(TC_NETLINK, session_start, started, native);
        let json = if native_succeeded {
            error_sample(
                TC_JSON,
                native.finished_at(),
                Duration::ZERO,
                MonitorErrorCode::Unsupported,
                "JSON fallback idle while native qdisc collection is available",
            )
        } else {
            let started = Instant::now();
            let result = fallback();
            self.tc_result_sample(TC_JSON, session_start, started, result)
        };
        vec![native, json]
    }

    fn tc_result_sample(
        &mut self,
        provider: &str,
        session_start: Instant,
        started: Instant,
        result: Result<Vec<tc::QdiscRow>, tc::CollectError>,
    ) -> ProviderSample {
        let finished = Instant::now();
        let finished_at = finished.saturating_duration_since(session_start);
        let collection_duration = finished.saturating_duration_since(started).min(finished_at);

        match result {
            Ok(rows) => match self.translate_qdisc_rows(rows) {
                Ok(readings) => provider_sample(
                    provider,
                    finished_at,
                    collection_duration,
                    ProviderHealth::Fresh,
                    readings,
                ),
                Err(error) => error_sample(
                    provider,
                    finished_at,
                    collection_duration,
                    error.code,
                    error.message,
                ),
            },
            Err(error) => {
                let error = AttemptError::tc(error);
                error_sample(
                    provider,
                    finished_at,
                    collection_duration,
                    error.code,
                    error.message,
                )
            }
        }
    }

    fn collect_netfilter_sample(
        &mut self,
        session_start: Instant,
        provider: &'static str,
        collect: fn() -> Result<netfilter::NetfilterRuleset, netfilter::CollectError>,
    ) -> ProviderSample {
        let started = Instant::now();
        let result = collect();
        let finished = Instant::now();
        let finished_at = finished.saturating_duration_since(session_start);
        let collection_duration = finished.saturating_duration_since(started).min(finished_at);

        match result {
            Ok(ruleset) => match self.translate_netfilter_ruleset(&ruleset) {
                Ok(translation) => {
                    let health = translation
                        .warning
                        .map_or(ProviderHealth::Fresh, |warning| ProviderHealth::Partial {
                            warning,
                        });
                    provider_sample(
                        provider,
                        finished_at,
                        collection_duration,
                        health,
                        translation.readings,
                    )
                }
                Err(error) => error_sample(
                    provider,
                    finished_at,
                    collection_duration,
                    error.code,
                    error.message,
                ),
            },
            Err(error) => {
                let error = AttemptError::netfilter(error);
                error_sample(
                    provider,
                    finished_at,
                    collection_duration,
                    error.code,
                    error.message,
                )
            }
        }
    }

    fn translate_netfilter_ruleset(
        &mut self,
        ruleset: &netfilter::NetfilterRuleset,
    ) -> Result<NetfilterTranslation, AttemptError> {
        let backend = netfilter_backend_label(&ruleset.backend).to_owned();
        let total_rules = ruleset
            .tables
            .iter()
            .flat_map(|table| &table.chains)
            .map(|chain| chain.rules.len())
            .sum::<usize>();
        let total_chains = ruleset
            .tables
            .iter()
            .map(|table| table.chains.len())
            .sum::<usize>();
        let mut readings = Vec::new();
        let mut retained = Vec::new();
        let mut unknown_families = 0_usize;

        for table in &ruleset.tables {
            let Some(family) = netfilter_family_label(&ruleset.backend, table.family.as_ref())
            else {
                unknown_families = unknown_families.saturating_add(1);
                continue;
            };
            for chain in &table.chains {
                if readings.len().saturating_add(NETFILTER_METRICS_PER_CHAIN)
                    > MAX_READINGS_PER_PROVIDER
                {
                    continue;
                }
                let labels =
                    netfilter_chain_labels(&backend, family, &table.name, chain, &ruleset.backend)
                        .map_err(AttemptError::internal)?;
                readings.push(SampleReading::observed(
                    MetricId::new("linux.netfilter.chain.rules").map_err(AttemptError::internal)?,
                    labels.clone(),
                    MetricReading::Gauge(chain.rules.len() as u64),
                ));
                readings.push(netfilter_policy_reading(&labels, chain)?);
                readings.push(netfilter_chain_type_reading(&labels, chain)?);
                retained.push((family.to_owned(), table, chain));
            }
        }

        let retained_chains = retained.len();
        let mut positions = vec![0_usize; retained_chains];
        let mut emitted_rules = 0_usize;
        'rules: loop {
            let mut found = false;
            for (chain_index, (family, table, chain)) in retained.iter().enumerate() {
                let position = positions[chain_index];
                let Some(rule) = chain.rules.get(position) else {
                    continue;
                };
                found = true;
                if readings.len().saturating_add(NETFILTER_METRICS_PER_RULE)
                    > MAX_READINGS_PER_PROVIDER
                {
                    break 'rules;
                }
                let duplicate_ordinal = chain.rules[..position]
                    .iter()
                    .filter(|candidate| {
                        candidate.handle == rule.handle && candidate.fingerprint == rule.fingerprint
                    })
                    .count();
                let verdict = netfilter_rule_verdict(rule);
                let identity = NetfilterRuleIdentity {
                    backend: backend.clone(),
                    family: family.clone(),
                    table: table.name.clone(),
                    chain: chain.name.clone(),
                    handle: rule.handle,
                    fingerprint: rule.fingerprint,
                    duplicate_ordinal,
                };
                let row_id = self.netfilter_rule_row_id(identity)?;
                let labels = netfilter_rule_labels(
                    &backend,
                    family,
                    &table.name,
                    &chain.name,
                    row_id,
                    rule.handle,
                    verdict,
                )
                .map_err(AttemptError::internal)?;
                let counters = netfilter_rule_counters(table, rule);
                readings.extend(netfilter_rule_readings(labels, position, rule, counters)?);
                positions[chain_index] = position.saturating_add(1);
                emitted_rules = emitted_rules.saturating_add(1);
            }
            if !found {
                break;
            }
        }

        let omitted_chains = total_chains.saturating_sub(retained_chains);
        let omitted_rules = total_rules.saturating_sub(emitted_rules);
        let flowtables = ruleset
            .nft_metadata
            .map_or(0, |metadata| metadata.flowtable_count);
        let warning = if omitted_chains != 0 || omitted_rules != 0 {
            Some(monitor_error(
                MonitorErrorCode::CardinalityLimit,
                format!(
                    "retained {retained_chains}/{total_chains} chains and {emitted_rules}/{total_rules} rules"
                ),
            ))
        } else if unknown_families != 0 {
            Some(monitor_error(
                MonitorErrorCode::SchemaMismatch,
                format!("ignored {unknown_families} tables with unknown nft family"),
            ))
        } else if flowtables != 0 {
            Some(monitor_error(
                MonitorErrorCode::Unsupported,
                format!(
                    "{flowtables} nft flowtables are active; classic rule visibility may be partial"
                ),
            ))
        } else {
            None
        };

        Ok(NetfilterTranslation { readings, warning })
    }

    fn netfilter_rule_row_id(
        &mut self,
        identity: NetfilterRuleIdentity,
    ) -> Result<u64, AttemptError> {
        if let Some(row_id) = self.netfilter_rule_row_ids.get(&identity) {
            return Ok(*row_id);
        }
        if self.netfilter_rule_row_ids.len() >= MAX_NETFILTER_RULE_ROW_IDS {
            return Err(AttemptError {
                code: MonitorErrorCode::CardinalityLimit,
                message: format!(
                    "netfilter rule identity history exceeds the {MAX_NETFILTER_RULE_ROW_IDS}-row session limit"
                ),
            });
        }
        let row_id = self.next_netfilter_rule_row_id;
        self.next_netfilter_rule_row_id = self.next_netfilter_rule_row_id.saturating_add(1);
        self.netfilter_rule_row_ids.insert(identity, row_id);
        Ok(row_id)
    }

    fn translate_qdisc_rows(
        &mut self,
        rows: Vec<tc::QdiscRow>,
    ) -> Result<Vec<SampleReading>, AttemptError> {
        let mut readings = Vec::with_capacity(rows.len().saturating_mul(QDISC_METRICS_PER_ROW));
        for row in rows {
            let Some(direction) = row.direction() else {
                continue;
            };
            let row_id = self.qdisc_row_id(&row.identity)?;
            let labels = qdisc_labels(&row, direction, row_id).map_err(AttemptError::internal)?;

            for (metric, value, bits) in [
                ("linux.tc.packets", row.packets, row.counter_bits.packets),
                ("linux.tc.bytes", row.bytes, row.counter_bits.bytes),
                ("linux.tc.drops", row.drops, row.counter_bits.drops),
                (
                    "linux.tc.overlimits",
                    row.overlimits,
                    row.counter_bits.overlimits,
                ),
                ("linux.tc.requeues", row.requeues, row.counter_bits.requeues),
            ] {
                let bits = match bits {
                    Some(32) => Some(CounterBits::Bits32),
                    Some(64) => Some(CounterBits::Bits64),
                    _ => None,
                };
                readings.push(qdisc_reading(
                    metric,
                    &labels,
                    value,
                    MetricKind::Counter,
                    bits,
                )?);
            }
            for (metric, value) in [
                ("linux.tc.backlog_bytes", row.backlog_bytes),
                ("linux.tc.backlog_packets", row.backlog_packets),
            ] {
                readings.push(qdisc_reading(
                    metric,
                    &labels,
                    value,
                    MetricKind::Gauge,
                    None,
                )?);
            }
            let has_extended_statistics = row.kind() == "fq_codel"
                || [
                    row.max_packet_bytes,
                    row.drop_overlimit,
                    row.new_flow_count,
                    row.ecn_marks,
                    row.new_flows_len,
                    row.old_flows_len,
                ]
                .into_iter()
                .any(|value| value.is_some());
            if has_extended_statistics {
                for (metric, value) in [
                    ("linux.tc.drop_overlimit", row.drop_overlimit),
                    ("linux.tc.new_flow_count", row.new_flow_count),
                    ("linux.tc.ecn_marks", row.ecn_marks),
                ] {
                    readings.push(qdisc_reading(
                        metric,
                        &labels,
                        value.map(u64::from),
                        MetricKind::Counter,
                        Some(CounterBits::Bits32),
                    )?);
                }
                for (metric, value) in [
                    ("linux.tc.max_packet_bytes", row.max_packet_bytes),
                    ("linux.tc.new_flows_len", row.new_flows_len),
                    ("linux.tc.old_flows_len", row.old_flows_len),
                ] {
                    readings.push(qdisc_reading(
                        metric,
                        &labels,
                        value.map(u64::from),
                        MetricKind::Gauge,
                        None,
                    )?);
                }
            }
        }
        Ok(readings)
    }

    fn qdisc_row_id(&mut self, identity: &tc::QdiscIdentity) -> Result<u64, AttemptError> {
        if let Some(row_id) = self.qdisc_row_ids.get(identity) {
            return Ok(*row_id);
        }
        if self.qdisc_row_ids.len() >= MAX_QDISC_ROW_IDS {
            return Err(AttemptError {
                code: MonitorErrorCode::CardinalityLimit,
                message: format!(
                    "qdisc identity history exceeds the {MAX_QDISC_ROW_IDS}-row session limit"
                ),
            });
        }

        let row_id = self.next_qdisc_row_id;
        self.next_qdisc_row_id = self.next_qdisc_row_id.saturating_add(1);
        self.qdisc_row_ids.insert(identity.clone(), row_id);
        Ok(row_id)
    }
}

struct NetfilterTranslation {
    readings: Vec<SampleReading>,
    warning: Option<MonitorError>,
}

fn netfilter_backend_label(backend: &netfilter::NetfilterBackend) -> &'static str {
    match backend {
        netfilter::NetfilterBackend::Nftables => "nftables",
        netfilter::NetfilterBackend::Iptables {
            implementation: netfilter::IptablesBackend::Nft,
            ..
        } => "iptables_nft",
        netfilter::NetfilterBackend::Iptables {
            implementation: netfilter::IptablesBackend::Legacy,
            ..
        } => "iptables_legacy",
        netfilter::NetfilterBackend::Iptables {
            implementation: netfilter::IptablesBackend::Unknown,
            ..
        } => "iptables_unknown",
    }
}

fn netfilter_family_label(
    backend: &netfilter::NetfilterBackend,
    family: Option<&netfilter::NftFamily>,
) -> Option<&'static str> {
    match backend {
        netfilter::NetfilterBackend::Iptables {
            family: netfilter::IptablesFamily::Ipv4,
            ..
        } => Some("ip"),
        netfilter::NetfilterBackend::Iptables {
            family: netfilter::IptablesFamily::Ipv6,
            ..
        } => Some("ip6"),
        netfilter::NetfilterBackend::Nftables => match family? {
            netfilter::NftFamily::Ip => Some("ip"),
            netfilter::NftFamily::Ip6 => Some("ip6"),
            netfilter::NftFamily::Inet => Some("inet"),
            netfilter::NftFamily::Arp => Some("arp"),
            netfilter::NftFamily::Bridge => Some("bridge"),
            netfilter::NftFamily::Netdev => Some("netdev"),
            netfilter::NftFamily::Other(_) => None,
        },
    }
}

fn netfilter_chain_labels(
    backend: &str,
    family: &str,
    table: &str,
    chain: &netfilter::NetfilterChain,
    raw_backend: &netfilter::NetfilterBackend,
) -> Result<MetricLabels, MonitorValidationError> {
    let mut labels = vec![
        (MetricLabel::Backend, backend.to_owned()),
        (MetricLabel::Family, family.to_owned()),
        (MetricLabel::Table, table.to_owned()),
        (MetricLabel::Chain, chain.name.clone()),
    ];
    let hook = chain
        .hook
        .as_ref()
        .and_then(netfilter_hook_label)
        .or_else(|| infer_iptables_hook(raw_backend, &chain.name));
    if let Some(hook) = hook {
        labels.push((MetricLabel::Hook, hook.to_owned()));
    }
    if let Some(priority) = chain.priority {
        labels.push((MetricLabel::Priority, priority.to_string()));
    }
    MetricLabels::new(labels)
}

fn netfilter_hook_label(hook: &netfilter::NetfilterHook) -> Option<&'static str> {
    match hook {
        netfilter::NetfilterHook::Ingress => Some("ingress"),
        netfilter::NetfilterHook::Prerouting => Some("prerouting"),
        netfilter::NetfilterHook::Input => Some("input"),
        netfilter::NetfilterHook::Forward => Some("forward"),
        netfilter::NetfilterHook::Output => Some("output"),
        netfilter::NetfilterHook::Postrouting => Some("postrouting"),
        netfilter::NetfilterHook::Egress => Some("egress"),
        netfilter::NetfilterHook::Other(_) => None,
    }
}

fn infer_iptables_hook(backend: &netfilter::NetfilterBackend, chain: &str) -> Option<&'static str> {
    if !matches!(backend, netfilter::NetfilterBackend::Iptables { .. }) {
        return None;
    }
    match chain {
        "PREROUTING" => Some("prerouting"),
        "INPUT" => Some("input"),
        "FORWARD" => Some("forward"),
        "OUTPUT" => Some("output"),
        "POSTROUTING" => Some("postrouting"),
        _ => None,
    }
}

fn netfilter_policy_reading(
    labels: &MetricLabels,
    chain: &netfilter::NetfilterChain,
) -> Result<SampleReading, AttemptError> {
    let metric = MetricId::new("linux.netfilter.chain.policy").map_err(AttemptError::internal)?;
    let Some(policy) = chain.policy.as_ref() else {
        return Ok(SampleReading::unavailable(
            metric,
            labels.clone(),
            UnavailableReason::NotApplicable,
        ));
    };
    let value = match policy {
        netfilter::ChainPolicy::Accept => "accept".to_owned(),
        netfilter::ChainPolicy::Drop => "drop".to_owned(),
        netfilter::ChainPolicy::None => "none".to_owned(),
        netfilter::ChainPolicy::Other(value) => value.clone(),
    };
    let value = StateValue::new(value).map_err(AttemptError::internal)?;
    Ok(SampleReading::observed(
        metric,
        labels.clone(),
        MetricReading::State(value),
    ))
}

fn netfilter_chain_type_reading(
    labels: &MetricLabels,
    chain: &netfilter::NetfilterChain,
) -> Result<SampleReading, AttemptError> {
    let metric = MetricId::new("linux.netfilter.chain.type").map_err(AttemptError::internal)?;
    let Some(chain_type) = chain.chain_type.as_ref() else {
        return Ok(SampleReading::unavailable(
            metric,
            labels.clone(),
            UnavailableReason::NotApplicable,
        ));
    };
    let value = StateValue::new(chain_type.clone()).map_err(AttemptError::internal)?;
    Ok(SampleReading::observed(
        metric,
        labels.clone(),
        MetricReading::State(value),
    ))
}

fn netfilter_rule_labels(
    backend: &str,
    family: &str,
    table: &str,
    chain: &str,
    row_id: u64,
    handle: Option<u64>,
    verdict: &str,
) -> Result<MetricLabels, MonitorValidationError> {
    let mut labels = vec![
        (MetricLabel::Backend, backend.to_owned()),
        (MetricLabel::Family, family.to_owned()),
        (MetricLabel::Table, table.to_owned()),
        (MetricLabel::Chain, chain.to_owned()),
        (MetricLabel::RowId, row_id.to_string()),
        (MetricLabel::Verdict, verdict.to_owned()),
    ];
    if let Some(handle) = handle {
        labels.push((MetricLabel::Handle, handle.to_string()));
    }
    MetricLabels::new(labels)
}

fn netfilter_rule_verdict(rule: &netfilter::NetfilterRule) -> &'static str {
    let mut observed = None;
    for action in &rule.actions {
        let netfilter::RuleAction::Verdict(verdict) = action else {
            continue;
        };
        let current = match verdict {
            netfilter::RuleVerdict::Accept => "accept",
            netfilter::RuleVerdict::Drop => "drop",
            netfilter::RuleVerdict::Reject => "reject",
            netfilter::RuleVerdict::Continue => "continue",
            netfilter::RuleVerdict::Return => "return",
            netfilter::RuleVerdict::Jump(_) => "jump",
            netfilter::RuleVerdict::Goto(_) => "goto",
            netfilter::RuleVerdict::Queue => "queue",
        };
        if observed.is_some_and(|previous| previous != current) {
            return "unknown";
        }
        observed = Some(current);
    }
    observed.unwrap_or_else(|| {
        if rule.actions.iter().any(|action| {
            matches!(
                action,
                netfilter::RuleAction::Dnat
                    | netfilter::RuleAction::Snat
                    | netfilter::RuleAction::Masquerade
                    | netfilter::RuleAction::Redirect
                    | netfilter::RuleAction::Other(_)
            )
        }) {
            "unknown"
        } else {
            "continue"
        }
    })
}

fn netfilter_rule_counters(
    table: &netfilter::NetfilterTable,
    rule: &netfilter::NetfilterRule,
) -> Option<netfilter::RuleCounters> {
    rule.counters.or_else(|| {
        rule.counter_reference.as_ref().and_then(|reference| {
            table
                .named_counters
                .iter()
                .find(|counter| counter.name == *reference)
                .map(|counter| counter.counters)
        })
    })
}

fn netfilter_rule_readings(
    labels: MetricLabels,
    position: usize,
    rule: &netfilter::NetfilterRule,
    counters: Option<netfilter::RuleCounters>,
) -> Result<Vec<SampleReading>, AttemptError> {
    let position = u64::try_from(position.saturating_add(1)).map_err(AttemptError::internal)?;
    let expression = bounded_rule_expression(&rule.summary);
    let expression = StateValue::new(expression).map_err(AttemptError::internal)?;
    let mut readings = vec![
        SampleReading::observed(
            MetricId::new("linux.netfilter.rule.position").map_err(AttemptError::internal)?,
            labels.clone(),
            MetricReading::Gauge(position),
        ),
        SampleReading::observed(
            MetricId::new("linux.netfilter.rule.expression").map_err(AttemptError::internal)?,
            labels.clone(),
            MetricReading::State(expression),
        ),
    ];
    for (metric, value) in [
        (
            "linux.netfilter.rule.packets",
            counters.map(|value| value.packets),
        ),
        (
            "linux.netfilter.rule.bytes",
            counters.map(|value| value.bytes),
        ),
    ] {
        let metric = MetricId::new(metric).map_err(AttemptError::internal)?;
        readings.push(match value {
            Some(value) => SampleReading::observed(
                metric,
                labels.clone(),
                MetricReading::Counter { value, bits: None },
            ),
            None => SampleReading::unavailable(metric, labels.clone(), UnavailableReason::Missing),
        });
    }
    Ok(readings)
}

fn bounded_rule_expression(summary: &str) -> String {
    let summary = if summary.is_empty() { "all" } else { summary };
    summary
        .bytes()
        .take(super::model::MAX_LABEL_VALUE_BYTES)
        .map(char::from)
        .collect()
}

impl super::session::MonitorCollector for BuiltinCollector {
    fn hardirq_snapshot(&self) -> Option<std::sync::Arc<super::hardirq::HardirqSnapshot>> {
        self.hardirq_snapshot.clone()
    }
    fn collection_focus(&self) -> Option<CollectionFocus> {
        Some(self.focus)
    }

    fn set_focus(&mut self, section: CollectionFocus) {
        if section.needs(Group::Hardirq) && !self.focus.needs(Group::Hardirq) {
            self.hardirq_snapshot = None;
        }
        if !section.needs(Group::Nic) {
            self.nic_configuration.stop();
        }
        for (group, cache) in [
            (Group::Tc, &mut self.tc_cache),
            (Group::Rules, &mut self.netfilter_cache),
            (Group::Nic, &mut self.nic_cache),
            (Group::Hardirq, &mut self.hardirq_cache),
        ] {
            if section.needs(group) && !self.focus.needs(group) {
                cache.collected_at = None;
            }
        }
        self.focus = section;
    }

    fn collect(&mut self, session_start: Instant) -> Vec<ProviderSample> {
        Self::collect(self, session_start)
    }

    fn network_namespace(&self) -> Option<String> {
        crate::collect::network_namespace(&self.paths)
    }
}

fn qdisc_labels(
    row: &tc::QdiscRow,
    direction: tc::QdiscDirection,
    row_id: u64,
) -> Result<MetricLabels, MonitorValidationError> {
    let direction = match direction {
        tc::QdiscDirection::Ingress => "ingress",
        tc::QdiscDirection::Egress => "egress",
    };
    MetricLabels::new([
        (MetricLabel::Interface, row.interface.clone()),
        (MetricLabel::Ifindex, row.ifindex.to_string()),
        (MetricLabel::Direction, direction.to_owned()),
        (MetricLabel::ObjectKind, "qdisc".to_owned()),
        (MetricLabel::QdiscKind, row.kind().to_owned()),
        (MetricLabel::RowId, row_id.to_string()),
        (MetricLabel::Execution, "software".to_owned()),
        (
            MetricLabel::QdiscAttachment,
            serde_json::to_string(&row.attachment())
                .expect("qdisc attachment contains only strings and a boolean"),
        ),
    ])
}

fn qdisc_reading(
    metric: &str,
    labels: &MetricLabels,
    value: Option<u64>,
    kind: MetricKind,
    counter_bits: Option<CounterBits>,
) -> Result<SampleReading, AttemptError> {
    let metric = MetricId::new(metric).map_err(AttemptError::internal)?;
    let Some(value) = value else {
        return Ok(SampleReading::unavailable(
            metric,
            labels.clone(),
            UnavailableReason::Missing,
        ));
    };
    let reading = match kind {
        MetricKind::Counter => MetricReading::Counter {
            value,
            bits: counter_bits,
        },
        MetricKind::Gauge => MetricReading::Gauge(value),
        MetricKind::State => {
            return Err(AttemptError::internal(
                "qdisc adapter cannot construct state readings",
            ))
        }
    };
    Ok(SampleReading::observed(metric, labels.clone(), reading))
}

fn collect_rtnetlink_sample(
    session_start: Instant,
    context: &mut rtnetlink::Context,
    cache: &mut LinkReadingsCache,
    share_metadata: bool,
) -> (ProviderSample, Option<rtnetlink::FreshLinkMetadata>) {
    let started = Instant::now();
    let result = context
        .collect(share_metadata)
        .map_err(AttemptError::rtnetlink);
    let finished_at = session_start.elapsed();
    let duration = started.elapsed().min(finished_at);
    let readings = result.and_then(|(links, metadata)| {
        cache
            .translate(&links)
            .map(|readings| (readings, metadata))
            .map_err(|error| AttemptError::internal(error.to_string()))
    });
    match readings {
        Ok((readings, metadata)) => {
            let sample = cache.sample.sample(
                RTNETLINK_LINK,
                finished_at,
                duration,
                ProviderHealth::Fresh,
                readings,
            );
            let metadata = if sample.health().is_fresh() {
                metadata
            } else {
                None
            };
            (sample, metadata)
        }
        Err(error) => (
            error_sample(
                RTNETLINK_LINK,
                finished_at,
                duration,
                error.code,
                error.message,
            ),
            None,
        ),
    }
}

fn translate_link_counters(
    links: &[rtnetlink::LinkCounters],
) -> Result<Vec<SampleReading>, MonitorValidationError> {
    let mut readings = Vec::with_capacity(links.len().saturating_mul(26));
    for link in links {
        let labels = MetricLabels::new([
            (MetricLabel::Interface, link.interface.clone()),
            (MetricLabel::Ifindex, link.ifindex.to_string()),
        ])?;
        for (name, value, bits) in link.counters() {
            let Some(descriptor) = descriptor_for_source(RTNETLINK_LINK, name) else {
                continue;
            };
            readings.push(SampleReading::observed(
                descriptor.metric_id(),
                labels.clone(),
                MetricReading::Counter {
                    value,
                    bits: Some(if bits == 64 {
                        CounterBits::Bits64
                    } else {
                        CounterBits::Bits32
                    }),
                },
            ));
        }
    }
    Ok(readings)
}

#[derive(Debug)]
struct LinkSchema {
    interface: String,
    ifindex: u32,
    fields: usize,
    carrier_changes: bool,
}

#[derive(Debug)]
struct LinkReadingTemplate {
    link: usize,
    counter: Option<usize>,
    identity: ReadingIdentity,
}

#[derive(Debug, Default)]
struct LinkReadingsCache {
    interfaces: Vec<LinkSchema>,
    templates: Vec<LinkReadingTemplate>,
    sample: ValidatedSampleCache,
}

impl LinkReadingsCache {
    fn translate(
        &mut self,
        links: &[rtnetlink::LinkCounters],
    ) -> Result<Vec<SampleReading>, MonitorValidationError> {
        let same_schema = self.interfaces.len() == links.len()
            && self.interfaces.iter().zip(links).all(|(cached, link)| {
                cached.interface == link.interface
                    && cached.ifindex == link.ifindex
                    && cached.fields == link.values.len()
                    && cached.carrier_changes == link.carrier_changes.is_some()
            });
        if !same_schema {
            // Oversized observations still reach the ordinary provider validation.
            if links
                .iter()
                .map(|link| link.counters().count())
                .sum::<usize>()
                > MAX_READINGS_PER_PROVIDER
            {
                *self = Self::default();
                return translate_link_counters(links);
            }
            let mut templates = Vec::new();
            for (index, link) in links.iter().enumerate() {
                let labels = interface_labels(&link.interface, link.ifindex)?;
                for (counter, (name, _, _)) in link.counters().enumerate() {
                    let Some(descriptor) = descriptor_for_source(RTNETLINK_LINK, name) else {
                        continue;
                    };
                    templates.push(LinkReadingTemplate {
                        link: index,
                        counter: (name != "carrier_changes").then_some(counter),
                        identity: ReadingIdentity {
                            metric: descriptor.metric_id(),
                            labels: labels.clone(),
                        },
                    });
                }
            }
            templates
                .sort_unstable_by(|left, right| left.identity.key().cmp(&right.identity.key()));
            self.interfaces = links
                .iter()
                .map(|link| LinkSchema {
                    interface: link.interface.clone(),
                    ifindex: link.ifindex,
                    fields: link.values.len(),
                    carrier_changes: link.carrier_changes.is_some(),
                })
                .collect();
            self.templates = templates;
        }
        Ok(self
            .templates
            .iter()
            .map(|template| {
                let link = &links[template.link];
                let (value, bits) = match template.counter {
                    Some(counter) => (link.values[counter], link.counter_bits),
                    None => (
                        u64::from(link.carrier_changes.expect("schema checked above")),
                        32,
                    ),
                };
                template.identity.observed(MetricReading::Counter {
                    value,
                    bits: Some(if bits == 64 {
                        CounterBits::Bits64
                    } else {
                        CounterBits::Bits32
                    }),
                })
            })
            .collect())
    }
}

#[derive(Debug)]
struct MetricReadingTemplate {
    input: usize,
    identity: ReadingIdentity,
    kind: MetricKind,
}

#[derive(Debug, Default)]
struct MetricReadingsCache {
    provider: Option<&'static str>,
    keys: Vec<MetricKey>,
    templates: Vec<MetricReadingTemplate>,
    sample: ValidatedSampleCache,
}

impl MetricReadingsCache {
    fn translate(
        &mut self,
        provider: &'static str,
        metrics: impl AsRef<[MetricSample]>,
    ) -> Result<Vec<SampleReading>, MonitorValidationError> {
        let metrics = metrics.as_ref();
        if metrics.len() > MAX_READINGS_PER_PROVIDER {
            *self = Self::default();
            return translate_metrics(provider, metrics);
        }
        // Include ignored rows and all source/group/label fields. A same-count
        // change can alter admission, counter width, or the descriptor's kind.
        let same_schema = self.provider == Some(provider)
            && self.keys.len() == metrics.len()
            && self
                .keys
                .iter()
                .zip(metrics)
                .all(|(key, sample)| key == &sample.key);
        if !same_schema {
            let mut templates = Vec::new();
            for (input, sample) in metrics.iter().enumerate() {
                let Some(reading) = translate_metric(provider, sample)? else {
                    continue;
                };
                let kind = match reading.outcome() {
                    super::ReadingOutcome::Observed(MetricReading::Counter { .. }) => {
                        MetricKind::Counter
                    }
                    super::ReadingOutcome::Observed(MetricReading::Gauge(_)) => MetricKind::Gauge,
                    _ => unreachable!("raw numeric translation emits counters or gauges"),
                };
                templates.push(MetricReadingTemplate {
                    input,
                    identity: ReadingIdentity::from_reading(&reading),
                    kind,
                });
            }
            templates
                .sort_unstable_by(|left, right| left.identity.key().cmp(&right.identity.key()));
            self.keys = metrics.iter().map(|sample| sample.key.clone()).collect();
            self.provider = Some(provider);
            self.templates = templates;
        }
        Ok(self
            .templates
            .iter()
            .map(|template| {
                let sample = &metrics[template.input];
                template.identity.observed(match template.kind {
                    MetricKind::Counter => MetricReading::Counter {
                        value: sample.value,
                        bits: counter_bits(sample),
                    },
                    MetricKind::Gauge => MetricReading::Gauge(sample.value),
                    MetricKind::State => {
                        unreachable!("raw numeric translation emits counters or gauges")
                    }
                })
            })
            .collect())
    }
}

fn collect_attempt<F, T>(
    session_start: Instant,
    provider: &'static str,
    caches: &mut BTreeMap<&'static str, MetricReadingsCache>,
    collect: F,
) -> ProviderSample
where
    F: FnOnce() -> Result<T, AttemptError>,
    T: AsRef<[MetricSample]>,
{
    let started = Instant::now();
    let result = collect();
    let finished = Instant::now();
    let finished_at = finished.saturating_duration_since(session_start);
    let collection_duration = finished.saturating_duration_since(started).min(finished_at);

    match result {
        Ok(metrics) => {
            let cache = caches.entry(provider).or_default();
            let result = cache.translate(provider, metrics).and_then(|readings| {
                cache.sample.build(
                    provider,
                    finished_at,
                    collection_duration,
                    ProviderHealth::Fresh,
                    readings,
                )
            });
            result.unwrap_or_else(|error| {
                error_sample(
                    provider,
                    finished_at,
                    collection_duration,
                    MonitorErrorCode::Internal,
                    format!("invalid translated reading: {error}"),
                )
            })
        }
        Err(error) => error_sample(
            provider,
            finished_at,
            collection_duration,
            error.code,
            error.message,
        ),
    }
}

fn translate_metrics(
    provider: &str,
    metrics: impl AsRef<[MetricSample]>,
) -> Result<Vec<SampleReading>, MonitorValidationError> {
    let mut readings = Vec::new();
    for sample in metrics.as_ref() {
        if let Some(reading) = translate_metric(provider, sample)? {
            readings.push(reading);
        }
    }
    Ok(readings)
}

fn translate_metric(
    provider: &str,
    sample: &MetricSample,
) -> Result<Option<SampleReading>, MonitorValidationError> {
    if provider_for_raw_source(&sample.key.source) != Some(provider) {
        return Ok(None);
    }
    if provider == PROC_SOFTNET
        && (sample.key.group != "softnet_cpu" || !sample.key.labels.contains_key("cpu"))
    {
        return Ok(None);
    }

    let raw_metric = match provider {
        PROC_SNMP | PROC_NETSTAT | PROC_SOCKSTAT | PROC_SOCKSTAT6 => {
            format!("{}.{}", sample.key.group, sample.key.metric)
        }
        PROC_SNMP6 | PROC_CONNTRACK | PROC_SOFTNET | PROC_SYS_NET_CORE | PROC_SYS_NET_IPV4
        | PROC_SOFTIRQS | PROC_INTERRUPTS | RTNETLINK_LINK | SYSFS_LINK | PROC_NET_DEV => {
            sample.key.metric.clone()
        }
        _ => return Ok(None),
    };
    let Some(descriptor) = descriptor_for_source(provider, &raw_metric) else {
        return Ok(None);
    };

    let labels = translated_labels(descriptor, sample)?;
    let reading = match descriptor.kind {
        MetricKind::Counter => MetricReading::Counter {
            value: sample.value,
            bits: counter_bits(sample),
        },
        MetricKind::Gauge => MetricReading::Gauge(sample.value),
        MetricKind::State => return Ok(None),
    };
    Ok(Some(SampleReading::observed(
        descriptor.metric_id(),
        labels,
        reading,
    )))
}

fn provider_for_raw_source(source: &str) -> Option<&'static str> {
    match source {
        "proc_net_snmp" => Some(PROC_SNMP),
        "proc_net_netstat" => Some(PROC_NETSTAT),
        "proc_net_snmp6" => Some(PROC_SNMP6),
        "proc_sockstat" => Some(PROC_SOCKSTAT),
        "proc_sockstat6" => Some(PROC_SOCKSTAT6),
        "proc_conntrack" => Some(PROC_CONNTRACK),
        "proc_softnet" => Some(PROC_SOFTNET),
        "proc_sys_net_core" => Some(PROC_SYS_NET_CORE),
        "proc_sys_net_ipv4" => Some(PROC_SYS_NET_IPV4),
        "proc_softirqs" => Some(PROC_SOFTIRQS),
        "proc_interrupts" => Some(PROC_INTERRUPTS),
        "rtnetlink_link_stats" => Some(RTNETLINK_LINK),
        "sys_class_net" => Some(SYSFS_LINK),
        "proc_net_dev" => Some(PROC_NET_DEV),
        _ => None,
    }
}

fn descriptor_for_source(provider: &str, raw_metric: &str) -> Option<&'static MetricDescriptor> {
    struct SourceIndex {
        exact: HashMap<(&'static str, &'static str), usize>,
        prefixes: Vec<(&'static str, &'static str, usize)>,
    }
    static INDEX: LazyLock<SourceIndex> = LazyLock::new(|| {
        let mut index = SourceIndex {
            exact: HashMap::new(),
            prefixes: Vec::new(),
        };
        for (ordinal, descriptor) in metric_catalog().iter().enumerate() {
            for source in descriptor.sources {
                index
                    .exact
                    .entry((source.provider, source.raw_metric))
                    .or_insert(ordinal);
                if let Some(prefix) = source.raw_metric.strip_suffix(".*") {
                    index.prefixes.push((source.provider, prefix, ordinal));
                }
            }
        }
        index
    });
    let exact = INDEX.exact.get(&(provider, raw_metric)).copied();
    let wildcard = INDEX.prefixes.iter().find_map(|(source, prefix, ordinal)| {
        (*source == provider && raw_metric.starts_with(prefix)).then_some(*ordinal)
    });
    exact
        .into_iter()
        .chain(wildcard)
        .min()
        .map(|index| &metric_catalog()[index])
}

#[cfg(test)]
fn collect_hardirq_sample(session_start: Instant, paths: &SystemPaths) -> ProviderSample {
    collect_hardirq_with_table(
        session_start,
        paths,
        &mut irq::HardirqCollector::default(),
        &mut None,
    )
}

fn collect_hardirq_with_table(
    session_start: Instant,
    paths: &SystemPaths,
    collector: &mut irq::HardirqCollector,
    latest: &mut Option<std::sync::Arc<super::hardirq::HardirqSnapshot>>,
) -> ProviderSample {
    let started = Instant::now();
    let result = collector.collect(&paths.proc_root, &paths.sys_root);
    let finished = Instant::now();
    let finished_at = finished.saturating_duration_since(session_start);
    let collection_duration = finished.saturating_duration_since(started).min(finished_at);

    match result {
        Ok(mut collection) => {
            *latest = Some(std::sync::Arc::new(super::hardirq::HardirqSnapshot::next(
                latest.as_deref(),
                finished_at,
                Ok(std::mem::take(&mut collection.table)),
            )));
            let skipped_shared_irqs = collection.skipped_shared_irqs;
            match translate_hardirq_collection(collection) {
                Ok(readings) => {
                    let health = if skipped_shared_irqs == 0 {
                        ProviderHealth::Fresh
                    } else {
                        ProviderHealth::Partial {
                        warning: monitor_error(
                            MonitorErrorCode::Unsupported,
                            format_args!(
                                "skipped {skipped_shared_irqs} IRQs mapped to multiple network interfaces"
                            ),
                        ),
                    }
                    };
                    provider_sample(
                        PROC_INTERRUPTS,
                        finished_at,
                        collection_duration,
                        health,
                        readings,
                    )
                }
                Err(error) => error_sample(
                    PROC_INTERRUPTS,
                    finished_at,
                    collection_duration,
                    MonitorErrorCode::Internal,
                    format!("invalid translated reading: {error}"),
                ),
            }
        }
        Err(error) => {
            *latest = Some(std::sync::Arc::new(super::hardirq::HardirqSnapshot::next(
                latest.as_deref(),
                finished_at,
                Err(error.to_string()),
            )));
            let error = AttemptError::irq(error);
            error_sample(
                PROC_INTERRUPTS,
                finished_at,
                collection_duration,
                error.code,
                error.message,
            )
        }
    }
}

fn translate_hardirq_collection(
    collection: irq::HardirqCollection,
) -> Result<Vec<SampleReading>, MonitorValidationError> {
    let mut readings = translate_metrics(PROC_INTERRUPTS, collection.metrics)?;
    for affinity in collection.affinities {
        readings.push(translate_affinity(affinity)?);
    }
    Ok(readings)
}

fn translate_affinity(
    affinity: irq::AffinityRecord,
) -> Result<SampleReading, MonitorValidationError> {
    let labels = interface_labels(&affinity.interface, affinity.ifindex)?;
    let metric = MetricId::new("linux.hardirq.affinity")?;
    match (affinity.complete, affinity.cpu_list) {
        (true, Some(cpu_list)) => Ok(SampleReading::observed(
            metric,
            labels,
            MetricReading::State(StateValue::new(cpu_list)?),
        )),
        (true, None) => Ok(SampleReading::unavailable(
            metric,
            labels,
            UnavailableReason::InvalidValue,
        )),
        (false, _) => Ok(SampleReading::unavailable(
            metric,
            labels,
            UnavailableReason::Missing,
        )),
    }
}

#[derive(Debug)]
struct ReadingIdentity {
    metric: MetricId,
    labels: MetricLabels,
}

impl ReadingIdentity {
    fn new(metric: &str, labels: MetricLabels) -> Self {
        Self {
            metric: MetricId::new(metric).expect("catalogued metric"),
            labels,
        }
    }

    fn from_reading(reading: &SampleReading) -> Self {
        Self {
            metric: reading.metric().clone(),
            labels: reading.labels().clone(),
        }
    }

    fn key(&self) -> (&MetricId, &MetricLabels) {
        (&self.metric, &self.labels)
    }

    fn observed(&self, value: MetricReading) -> SampleReading {
        SampleReading::observed(self.metric.clone(), self.labels.clone(), value)
    }

    fn state(&self, value: impl Into<String>) -> SampleReading {
        self.observed(MetricReading::State(
            StateValue::new(value).expect("collected NIC state value is valid"),
        ))
    }

    fn unavailable(&self, reason: UnavailableReason) -> SampleReading {
        SampleReading::unavailable(self.metric.clone(), self.labels.clone(), reason)
    }
}

#[derive(Debug, Default)]
struct CanonicalReadingOrder {
    identities: Vec<ReadingIdentity>,
    swaps: Vec<(usize, usize)>,
}

impl CanonicalReadingOrder {
    fn reorder(&mut self, readings: &mut [SampleReading]) {
        if readings.len() > MAX_READINGS_PER_PROVIDER {
            *self = Self::default();
            return;
        }
        let same_schema = self.identities.len() == readings.len()
            && self
                .identities
                .iter()
                .zip(readings.iter())
                .all(|(identity, reading)| identity.key() == (reading.metric(), reading.labels()));
        if !same_schema {
            self.identities = readings.iter().map(ReadingIdentity::from_reading).collect();
            let mut order = (0..readings.len()).collect::<Vec<_>>();
            order.sort_unstable_by(|&left, &right| {
                self.identities[left]
                    .key()
                    .cmp(&self.identities[right].key())
            });
            let mut destinations = vec![0; order.len()];
            for (destination, source) in order.into_iter().enumerate() {
                destinations[source] = destination;
            }
            self.swaps.clear();
            // Record permutation cycles once; stable schemas need only an
            // identity comparison and these in-place swaps of current readings.
            for index in 0..destinations.len() {
                while destinations[index] != index {
                    let destination = destinations[index];
                    self.swaps.push((index, destination));
                    destinations.swap(index, destination);
                }
            }
        }
        for &(left, right) in &self.swaps {
            readings.swap(left, right);
        }
    }
}

#[derive(Debug)]
struct NicStatisticTemplate {
    name: String,
    labels: Option<MetricLabels>,
}

#[derive(Debug)]
struct NicInterfaceReadings {
    ifindex: u32,
    hardware_backed: bool,
    kind: ReadingIdentity,
    link_state: ReadingIdentity,
    mtu: ReadingIdentity,
    sysfs: [ReadingIdentity; 4],
    statistics_status: ReadingIdentity,
    statistics_metric: MetricId,
    statistics: Vec<NicStatisticTemplate>,
    standard_statistics: usize,
}

impl NicInterfaceReadings {
    fn new(interface: &nic::NicInterface) -> Result<Self, MonitorValidationError> {
        let labels = interface_labels(&interface.interface, interface.ifindex)?;
        Ok(Self {
            ifindex: interface.ifindex,
            hardware_backed: interface.hardware_backed,
            kind: ReadingIdentity::new("linux.nic.interface_kind", labels.clone()),
            link_state: ReadingIdentity::new("linux.nic.link_state", labels.clone()),
            mtu: ReadingIdentity::new("linux.nic.mtu", labels.clone()),
            sysfs: ["Driver", "RX Queues", "TX Queues", "TX Queue Length"].map(|name| {
                ReadingIdentity::new(
                    super::RAW_NIC_SETTING_METRIC_ID,
                    nic_statistic_labels(interface, name)
                        .expect("collected sysfs NIC setting labels are valid"),
                )
            }),
            statistics_status: ReadingIdentity::new(
                super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
                labels,
            ),
            statistics_metric: MetricId::new(super::RAW_PRIVATE_NIC_METRIC_ID)
                .expect("catalogued raw NIC metric"),
            statistics: Vec::new(),
            standard_statistics: 0,
        })
    }

    fn append_statistics(
        &mut self,
        interface: &nic::NicInterface,
        statistics: &nic::NicStatistics,
        readings: &mut Vec<SampleReading>,
    ) {
        // Compare ordered names, not just their count: drivers can replace or reorder fields.
        let same_schema = self.standard_statistics == statistics.standard.len()
            && self.statistics.len() == statistics.standard.len() + statistics.private.len()
            && self
                .statistics
                .iter()
                .zip(nic_statistic_values(statistics))
                .all(|(template, (name, _))| template.name == name);
        if !same_schema {
            self.statistics = nic_statistic_values(statistics)
                .map(|(name, _)| NicStatisticTemplate {
                    name: name.to_owned(),
                    labels: nic_statistic_labels(interface, name).ok(),
                })
                .collect();
            self.standard_statistics = statistics.standard.len();
        }
        readings.extend(
            self.statistics
                .iter()
                .zip(nic_statistic_values(statistics))
                .filter_map(|(template, (_, value))| {
                    template.labels.as_ref().map(|labels| {
                        SampleReading::observed(
                            self.statistics_metric.clone(),
                            labels.clone(),
                            MetricReading::Gauge(value),
                        )
                    })
                }),
        );
    }
}

#[derive(Debug, Default)]
struct NicReadingsCache {
    interfaces: BTreeMap<String, NicInterfaceReadings>,
    state_order: CanonicalReadingOrder,
    statistics_order: CanonicalReadingOrder,
    state_sample: ValidatedSampleCache,
    statistics_sample: ValidatedSampleCache,
}

impl NicReadingsCache {
    fn retain(&mut self, collection: &nic::NicCollection) {
        self.interfaces.retain(|name, cached| {
            collection.interfaces.iter().any(|interface| {
                interface.interface == *name
                    && interface.ifindex == cached.ifindex
                    && interface.hardware_backed == cached.hardware_backed
            })
        });
    }

    fn for_interface(
        &mut self,
        interface: &nic::NicInterface,
    ) -> Result<&mut NicInterfaceReadings, MonitorValidationError> {
        if !self.interfaces.contains_key(interface.interface.as_str()) {
            self.interfaces.insert(
                interface.interface.clone(),
                NicInterfaceReadings::new(interface)?,
            );
        }
        Ok(self
            .interfaces
            .get_mut(interface.interface.as_str())
            .expect("interface identities were cached"))
    }
}

fn nic_statistic_labels(
    interface: &nic::NicInterface,
    statistic: &str,
) -> Result<MetricLabels, MonitorValidationError> {
    MetricLabels::new([
        (MetricLabel::Interface, interface.interface.clone()),
        (MetricLabel::Ifindex, interface.ifindex.to_string()),
        (MetricLabel::Statistic, statistic.to_owned()),
    ])
}

fn nic_statistic_values(statistics: &nic::NicStatistics) -> impl Iterator<Item = (&str, u64)> {
    statistics
        .standard
        .iter()
        .map(|statistic| (statistic.statistic.as_str(), statistic.value))
        .chain(
            statistics
                .private
                .iter()
                .map(|statistic| (statistic.name.as_str(), statistic.value)),
        )
}

fn translate_nic_collection(
    collection: &nic::NicCollection,
    current_timing: NicCollectionTiming,
    settings_sample: ProviderSample,
    cache: &mut NicReadingsCache,
) -> Vec<ProviderSample> {
    let NicCollectionTiming {
        finished_at,
        collection_duration,
    } = current_timing;
    let mut state_groups = Vec::new();
    let mut ethtool_groups = Vec::new();
    let mut ethtool_failures = Vec::new();
    let mut ethtool_partial = Vec::new();
    let mut hardware_interfaces = 0_usize;
    cache.retain(collection);
    for interface in &collection.interfaces {
        let cached = match cache.for_interface(interface) {
            Ok(cached) => cached,
            Err(error) => {
                return vec![error_sample(
                    SYSFS_NIC,
                    finished_at,
                    collection_duration,
                    MonitorErrorCode::Internal,
                    error,
                )]
            }
        };
        let interface_kind = if interface.hardware_backed {
            "physical"
        } else {
            "virtual"
        };
        let mut state_group = vec![cached.kind.state(interface_kind)];
        match nic_state_value(&interface.operstate) {
            Some(value) => state_group.push(cached.link_state.state(value)),
            None => state_group.push(
                cached
                    .link_state
                    .unavailable(UnavailableReason::InvalidValue),
            ),
        }
        let sysfs_values = [
            interface.sysfs.driver.clone(),
            interface
                .sysfs
                .rx_queue_count
                .map(|value| value.to_string()),
            interface
                .sysfs
                .tx_queue_count
                .map(|value| value.to_string()),
            interface.sysfs.tx_queue_len.map(|value| value.to_string()),
        ];
        for (identity, value) in cached.sysfs.iter().zip(sysfs_values) {
            state_group.push(match value {
                Some(value) => identity.state(value),
                None => identity.unavailable(UnavailableReason::Missing),
            });
        }
        state_group.push(match interface.sysfs.mtu {
            Some(mtu) => cached.mtu.observed(MetricReading::Gauge(u64::from(mtu))),
            None => cached.mtu.unavailable(UnavailableReason::Missing),
        });
        state_groups.push(state_group);

        match &interface.ethtool {
            nic::EthtoolOutcome::NotHardwareInterface => {}
            nic::EthtoolOutcome::Collected(statistics) => {
                hardware_interfaces = hardware_interfaces.saturating_add(1);
                let mut readings = vec![cached.statistics_status.state("complete")];
                cached.append_statistics(interface, statistics, &mut readings);
                ethtool_groups.push(readings);
            }
            nic::EthtoolOutcome::Partial {
                statistics,
                rejected_lines,
                omitted_private,
            } => {
                hardware_interfaces = hardware_interfaces.saturating_add(1);
                let status = if *rejected_lines > 0 {
                    "partial_schema_mismatch"
                } else {
                    "partial_cardinality_limit"
                };
                let mut readings = vec![cached.statistics_status.state(status)];
                cached.append_statistics(interface, statistics, &mut readings);
                ethtool_groups.push(readings);
                ethtool_partial.push((
                    interface.interface.as_str(),
                    *rejected_lines,
                    *omitted_private,
                ));
            }
            nic::EthtoolOutcome::Failed(error) => {
                hardware_interfaces = hardware_interfaces.saturating_add(1);
                ethtool_groups.push(vec![cached
                    .statistics_status
                    .state(ethtool_failure_status(error))]);
                ethtool_failures.push((interface.interface.as_str(), error));
            }
        }
    }
    let ethtool_labels = ethtool_groups
        .iter()
        .filter_map(|group| group.first().map(|reading| reading.labels().clone()))
        .collect::<Vec<_>>();
    let BoundedInterfaceReadings {
        readings: mut state_readings,
        omitted_primary: omitted_interface_kinds,
        omitted_payload: omitted_sysfs_fields,
        ..
    } = interleave_readings(state_groups, MAX_READINGS_PER_PROVIDER);
    let BoundedInterfaceReadings {
        readings: mut ethtool_readings,
        omitted_primary: omitted_statistics_statuses,
        omitted_payload: omitted_statistics,
        omitted_payload_by_group: ethtool_omitted_by_interface,
    } = interleave_readings(ethtool_groups, MAX_READINGS_PER_PROVIDER);
    mark_cardinality_limited_statuses(
        &mut ethtool_readings,
        super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
        &ethtool_labels,
        &ethtool_omitted_by_interface,
    );
    cache.state_order.reorder(&mut state_readings);
    cache.statistics_order.reorder(&mut ethtool_readings);

    let sysfs_sample = if state_readings.is_empty() && !collection.errors.is_empty() {
        error_sample(
            SYSFS_NIC,
            finished_at,
            collection_duration,
            MonitorErrorCode::Io,
            &collection.errors[0].detail,
        )
    } else {
        let health = if omitted_interface_kinds > 0 || omitted_sysfs_fields > 0 {
            let mut diagnostic = format!(
                "NIC sysfs results exceeded the {MAX_READINGS_PER_PROVIDER}-reading provider limit; omitted {omitted_interface_kinds} interface kind readings and {omitted_sysfs_fields} link-state or setting readings"
            );
            if let Some(error) = collection.errors.first() {
                write!(
                    &mut diagnostic,
                    "; first collection error: {}",
                    error.detail
                )
                .expect("writing to a String cannot fail");
            }
            ProviderHealth::Partial {
                warning: monitor_error(MonitorErrorCode::CardinalityLimit, diagnostic),
            }
        } else {
            collection
                .errors
                .first()
                .map_or(ProviderHealth::Fresh, |error| ProviderHealth::Partial {
                    warning: monitor_error(
                        MonitorErrorCode::Io,
                        format_args!(
                            "NIC sysfs collection was incomplete; first error: {}",
                            error.detail
                        ),
                    ),
                })
        };
        cache.state_sample.sample(
            SYSFS_NIC,
            finished_at,
            collection_duration,
            health,
            state_readings,
        )
    };

    let ethtool_sample = if !ethtool_readings.is_empty() {
        let issue_count = ethtool_failures.len().saturating_add(ethtool_partial.len());
        let health = if omitted_statistics_statuses > 0 || omitted_statistics > 0 {
            let mut diagnostic = if omitted_statistics_statuses > 0 {
                format!(
                    "ethtool statistics cardinality limit {MAX_READINGS_PER_PROVIDER}; omitted {omitted_statistics_statuses} interface statuses, {omitted_statistics} statistics; failures {}; schema partials {}",
                    ethtool_failures.len(),
                    ethtool_partial.len()
                )
            } else {
                format!(
                    "ethtool statistics cardinality limit {MAX_READINGS_PER_PROVIDER}; omitted {omitted_statistics} statistics; failures {}; schema partials {}",
                    ethtool_failures.len(),
                    ethtool_partial.len()
                )
            };
            if let Some((interface, failure)) = ethtool_failures.first() {
                write!(
                    &mut diagnostic,
                    "; first failure {interface}: {}",
                    ethtool_failure_status(failure)
                )
                .expect("writing to a String cannot fail");
            }
            if let Some((interface, rejected_lines, omitted_private)) = ethtool_partial.first() {
                write!(
                    &mut diagnostic,
                    "; first schema partial {interface}: rejected={rejected_lines}, private_omitted={omitted_private}"
                )
                .expect("writing to a String cannot fail");
            }
            ProviderHealth::Partial {
                warning: monitor_error(MonitorErrorCode::CardinalityLimit, diagnostic),
            }
        } else if let Some((interface, failure)) = ethtool_failures.first() {
            let (code, _) = ethtool_failure_class(failure);
            ProviderHealth::Partial {
                warning: monitor_error(
                    code,
                    format_args!(
                        "{issue_count}/{hardware_interfaces} hardware interface ethtool results incomplete; first {interface}: {failure}"
                    ),
                ),
            }
        } else if let Some((interface, rejected_lines, omitted_private)) = ethtool_partial.first() {
            ProviderHealth::Partial {
                warning: monitor_error(
                    MonitorErrorCode::SchemaMismatch,
                    format_args!(
                        "{issue_count}/{hardware_interfaces} hardware interface ethtool results partial; first {interface}: {rejected_lines} rejected lines, {omitted_private} omitted statistics"
                    ),
                ),
            }
        } else {
            ProviderHealth::Fresh
        };
        cache.statistics_sample.sample(
            ETHTOOL_TEXT,
            finished_at,
            collection_duration,
            health,
            ethtool_readings,
        )
    } else if let Some((_, error)) = ethtool_failures.first() {
        ethtool_error_sample(ETHTOOL_TEXT, finished_at, collection_duration, error)
    } else if let Some((interface, rejected_lines, omitted_private)) = ethtool_partial.first() {
        error_sample(
            ETHTOOL_TEXT,
            finished_at,
            collection_duration,
            MonitorErrorCode::SchemaMismatch,
            format_args!(
                "ethtool returned no usable statistics for {interface}: {rejected_lines} rejected lines, {omitted_private} omitted statistics"
            ),
        )
    } else {
        let diagnostic = if hardware_interfaces == 0 {
            "no hardware-backed network interface is visible"
        } else {
            "ethtool returned no bounded statistics"
        };
        cache.statistics_sample.sample(
            ETHTOOL_TEXT,
            finished_at,
            collection_duration,
            ProviderHealth::Unsupported {
                reason: monitor_error(MonitorErrorCode::Unsupported, diagnostic),
            },
            Vec::new(),
        )
    };
    vec![sysfs_sample, settings_sample, ethtool_sample]
}

fn translate_nic_settings(
    collection: &nic::NicCollection,
    timing: NicCollectionTiming,
) -> ProviderSample {
    let mut settings_groups = Vec::new();
    let mut settings_failures = Vec::new();
    let mut settings_partial = Vec::new();
    let mut settings_pending = Vec::new();
    let mut settings_interfaces = 0_usize;
    for interface in &collection.interfaces {
        if matches!(
            interface.settings,
            nic::EthtoolSettingsOutcome::NotHardwareInterface
        ) && interface.channels.is_empty()
            && interface.fallback_settings.is_empty()
        {
            continue;
        }
        let labels = match interface_labels(&interface.interface, interface.ifindex) {
            Ok(labels) => labels,
            Err(error) => {
                return error_sample(
                    ETHTOOL_LINK_TEXT,
                    timing.finished_at,
                    timing.collection_duration,
                    MonitorErrorCode::Internal,
                    error,
                )
            }
        };
        match &interface.settings {
            nic::EthtoolSettingsOutcome::NotHardwareInterface => {
                settings_interfaces = settings_interfaces.saturating_add(1);
                settings_groups.push(vec![ethtool_status_reading(
                    super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
                    labels,
                    "unsupported",
                )]);
            }
            nic::EthtoolSettingsOutcome::RefreshPending => {
                settings_interfaces = settings_interfaces.saturating_add(1);
                settings_groups.push(vec![ethtool_status_reading(
                    super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
                    labels,
                    "refresh_pending",
                )]);
                settings_pending.push(interface.interface.as_str());
            }
            nic::EthtoolSettingsOutcome::Collected(settings) => {
                settings_interfaces = settings_interfaces.saturating_add(1);
                let mut readings = vec![ethtool_status_reading(
                    super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
                    labels,
                    "complete",
                )];
                append_ethtool_setting_readings(interface, settings, &mut readings);
                settings_groups.push(readings);
            }
            nic::EthtoolSettingsOutcome::Partial {
                settings,
                rejected_lines,
            } => {
                settings_interfaces = settings_interfaces.saturating_add(1);
                let mut readings = vec![ethtool_status_reading(
                    super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
                    labels,
                    "partial_schema_mismatch",
                )];
                append_ethtool_setting_readings(interface, settings, &mut readings);
                settings_groups.push(readings);
                settings_partial.push((interface.interface.as_str(), *rejected_lines));
            }
            nic::EthtoolSettingsOutcome::Failed(error) => {
                settings_interfaces = settings_interfaces.saturating_add(1);
                settings_groups.push(vec![ethtool_status_reading(
                    super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
                    labels,
                    ethtool_failure_status(error),
                )]);
                settings_failures.push((interface.interface.as_str(), error));
            }
        }
        if let Some(readings) = settings_groups.last_mut() {
            append_ethtool_setting_readings(
                interface,
                &nic::EthtoolSettings {
                    fields: interface
                        .channels
                        .iter()
                        .chain(&interface.fallback_settings)
                        .cloned()
                        .collect(),
                },
                readings,
            );
        }
    }
    let settings_labels = settings_groups
        .iter()
        .filter_map(|group| group.first().map(|reading| reading.labels().clone()))
        .collect::<Vec<_>>();
    let BoundedInterfaceReadings {
        readings: mut settings_readings,
        omitted_primary: omitted_setting_statuses,
        omitted_payload: omitted_setting_fields,
        omitted_payload_by_group: settings_omitted_by_interface,
    } = interleave_readings(settings_groups, MAX_READINGS_PER_PROVIDER);
    mark_cardinality_limited_statuses(
        &mut settings_readings,
        super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
        &settings_labels,
        &settings_omitted_by_interface,
    );

    let settings_timing = if settings_interfaces == 0 {
        NicCollectionTiming {
            finished_at: timing.finished_at,
            collection_duration: Duration::ZERO,
        }
    } else {
        timing
    };
    if !settings_readings.is_empty() {
        let issue_count = settings_failures
            .len()
            .saturating_add(settings_partial.len())
            .saturating_add(settings_pending.len());
        let health = if omitted_setting_statuses > 0 || omitted_setting_fields > 0 {
            let mut diagnostic = if omitted_setting_statuses > 0 {
                format!(
                    "ethtool settings cardinality limit {MAX_READINGS_PER_PROVIDER}; omitted {omitted_setting_statuses} interface statuses, {omitted_setting_fields} setting fields; failures {}; schema partials {}; pending {}",
                    settings_failures.len(),
                    settings_partial.len(),
                    settings_pending.len()
                )
            } else {
                format!(
                    "ethtool settings cardinality limit {MAX_READINGS_PER_PROVIDER}; omitted {omitted_setting_fields} setting fields; failures {}; schema partials {}; pending {}",
                    settings_failures.len(),
                    settings_partial.len(),
                    settings_pending.len()
                )
            };
            if let Some((interface, failure)) = settings_failures.first() {
                write!(
                    &mut diagnostic,
                    "; first failure {interface}: {}",
                    ethtool_failure_status(failure)
                )
                .expect("writing to a String cannot fail");
            }
            if let Some((interface, rejected_lines)) = settings_partial.first() {
                write!(
                    &mut diagnostic,
                    "; first schema partial {interface}: rejected={rejected_lines}"
                )
                .expect("writing to a String cannot fail");
            }
            ProviderHealth::Partial {
                warning: monitor_error(MonitorErrorCode::CardinalityLimit, diagnostic),
            }
        } else if let Some((interface, failure)) = settings_failures.first() {
            let (code, _) = ethtool_failure_class(failure);
            ProviderHealth::Partial {
                warning: monitor_error(
                    code,
                    format_args!(
                        "{issue_count}/{settings_interfaces} hardware interface ethtool setting results incomplete; first {interface}: {failure}"
                    ),
                ),
            }
        } else if let Some((interface, rejected_lines)) = settings_partial.first() {
            ProviderHealth::Partial {
                warning: monitor_error(
                    MonitorErrorCode::SchemaMismatch,
                    format_args!(
                        "{issue_count}/{settings_interfaces} hardware interface ethtool setting results partial; first {interface}: {rejected_lines} rejected lines"
                    ),
                ),
            }
        } else if let Some(interface) = settings_pending.first() {
            ProviderHealth::Partial {
                warning: monitor_error(
                    MonitorErrorCode::Internal,
                    format_args!(
                        "{issue_count}/{settings_interfaces} hardware interface ethtool setting results pending after collection; first {interface}"
                    ),
                ),
            }
        } else {
            ProviderHealth::Fresh
        };
        provider_sample(
            ETHTOOL_LINK_TEXT,
            settings_timing.finished_at,
            settings_timing.collection_duration,
            health,
            settings_readings,
        )
    } else if let Some((_, error)) = settings_failures.first() {
        ethtool_error_sample(
            ETHTOOL_LINK_TEXT,
            settings_timing.finished_at,
            settings_timing.collection_duration,
            error,
        )
    } else {
        provider_sample(
            ETHTOOL_LINK_TEXT,
            settings_timing.finished_at,
            settings_timing.collection_duration,
            ProviderHealth::Unsupported {
                reason: monitor_error(
                    MonitorErrorCode::Unsupported,
                    if settings_interfaces == 0 {
                        "no hardware-backed network interface is visible"
                    } else {
                        "ethtool returned no bounded link settings"
                    },
                ),
            },
            Vec::new(),
        )
    }
}

struct BoundedInterfaceReadings {
    readings: Vec<SampleReading>,
    omitted_primary: usize,
    omitted_payload: usize,
    omitted_payload_by_group: Vec<usize>,
}

fn interleave_readings(groups: Vec<Vec<SampleReading>>, limit: usize) -> BoundedInterfaceReadings {
    let total = groups.iter().map(Vec::len).sum::<usize>();
    let original_lengths = groups.iter().map(Vec::len).collect::<Vec<_>>();
    let mut admitted = vec![0; groups.len()];
    let mut count = 0;
    while count < limit {
        let mut progressed = false;
        for (length, admitted) in original_lengths.iter().zip(&mut admitted) {
            if *admitted < *length {
                *admitted += 1;
                count += 1;
                progressed = true;
                if count == limit {
                    break;
                }
            }
        }
        if !progressed {
            break;
        }
    }
    let remaining_by_group = original_lengths
        .iter()
        .zip(&admitted)
        .map(|(length, admitted)| length - admitted)
        .collect::<Vec<_>>();
    // Admission stays round-robin. Pack each admitted group contiguously to
    // avoid scrambling stable interface order before canonical sample sorting.
    let mut readings = Vec::with_capacity(total.min(limit));
    for (group, count) in groups.into_iter().zip(admitted) {
        readings.extend(group.into_iter().take(count));
    }
    let mut omitted_primary = 0_usize;
    let omitted_payload_by_group = original_lengths
        .iter()
        .zip(remaining_by_group)
        .map(|(original, remaining)| {
            if *original > 0 && *original == remaining {
                omitted_primary = omitted_primary.saturating_add(1);
                remaining.saturating_sub(1)
            } else {
                remaining
            }
        })
        .collect::<Vec<_>>();
    let omitted_payload = omitted_payload_by_group.iter().sum::<usize>();
    debug_assert_eq!(
        total.saturating_sub(readings.len()),
        omitted_primary.saturating_add(omitted_payload)
    );
    BoundedInterfaceReadings {
        readings,
        omitted_primary,
        omitted_payload,
        omitted_payload_by_group,
    }
}

fn interface_labels(interface: &str, ifindex: u32) -> Result<MetricLabels, MonitorValidationError> {
    MetricLabels::new([
        (MetricLabel::Interface, interface.to_owned()),
        (MetricLabel::Ifindex, ifindex.to_string()),
    ])
}

fn ethtool_status_reading(metric: &str, labels: MetricLabels, status: &str) -> SampleReading {
    SampleReading::observed(
        MetricId::new(metric).expect("catalogued ethtool status metric"),
        labels,
        MetricReading::State(super::StateValue::new(status).expect("closed ethtool status value")),
    )
}

fn mark_cardinality_limited_statuses(
    readings: &mut [SampleReading],
    metric: &str,
    labels: &[MetricLabels],
    omitted_by_interface: &[usize],
) {
    for (labels, omitted) in labels.iter().zip(omitted_by_interface) {
        if *omitted == 0 {
            continue;
        }
        let Some(status) = readings
            .iter_mut()
            .find(|reading| reading.metric().as_str() == metric && reading.labels() == labels)
        else {
            continue;
        };
        *status = SampleReading::observed(
            status.metric().clone(),
            status.labels().clone(),
            MetricReading::State(
                StateValue::new("partial_cardinality_limit").expect("closed ethtool status value"),
            ),
        );
    }
}

const fn ethtool_failure_status(failure: &nic::EthtoolFailure) -> &'static str {
    match failure {
        nic::EthtoolFailure::CommandNotFound => "command_not_found",
        nic::EthtoolFailure::PermissionDenied { .. } => "permission_denied",
        nic::EthtoolFailure::Unsupported { .. } => "unsupported",
        nic::EthtoolFailure::InterfaceUnavailable { .. } => "interface_unavailable",
        nic::EthtoolFailure::TimedOut => "timed_out",
        nic::EthtoolFailure::OutputTooLarge { .. } => "output_limit",
        nic::EthtoolFailure::InvalidOutput => "invalid_output",
        nic::EthtoolFailure::ExitFailure { .. } => "command_failed",
        nic::EthtoolFailure::Io { .. } => "io_error",
    }
}

fn nic_state_value(state: &nic::OperState) -> Option<&'static str> {
    match state {
        nic::OperState::Up => Some("up"),
        nic::OperState::Down => Some("down"),
        nic::OperState::Unknown => Some("unknown"),
        nic::OperState::Dormant => Some("dormant"),
        nic::OperState::LowerLayerDown => Some("lower_layer_down"),
        nic::OperState::NotPresent => Some("not_present"),
        nic::OperState::Testing => Some("testing"),
        nic::OperState::Other(_) | nic::OperState::Unavailable => None,
    }
}

fn append_ethtool_setting_readings(
    interface: &nic::NicInterface,
    settings: &nic::EthtoolSettings,
    readings: &mut Vec<SampleReading>,
) {
    for field in &settings.fields {
        let Ok(labels) = nic_statistic_labels(interface, &field.name) else {
            continue;
        };
        let Ok(value) = StateValue::new(field.value.clone()) else {
            continue;
        };
        readings.push(SampleReading::observed(
            MetricId::new(super::RAW_NIC_SETTING_METRIC_ID)
                .expect("catalogued ethtool setting metric"),
            labels,
            MetricReading::State(value),
        ));
    }
}

fn ethtool_error_sample(
    provider: &str,
    finished_at: Duration,
    collection_duration: Duration,
    failure: &nic::EthtoolFailure,
) -> ProviderSample {
    let (code, unsupported) = ethtool_failure_class(failure);
    if unsupported {
        provider_sample(
            provider,
            finished_at,
            collection_duration,
            ProviderHealth::Unsupported {
                reason: monitor_error(code, failure),
            },
            Vec::new(),
        )
    } else {
        error_sample(provider, finished_at, collection_duration, code, failure)
    }
}

fn ethtool_failure_class(failure: &nic::EthtoolFailure) -> (MonitorErrorCode, bool) {
    match failure {
        nic::EthtoolFailure::CommandNotFound => (MonitorErrorCode::NotFound, false),
        nic::EthtoolFailure::PermissionDenied { .. } => (MonitorErrorCode::PermissionDenied, false),
        nic::EthtoolFailure::Unsupported { .. } => (MonitorErrorCode::Unsupported, true),
        nic::EthtoolFailure::InterfaceUnavailable { .. } => (MonitorErrorCode::NotFound, false),
        nic::EthtoolFailure::TimedOut => (MonitorErrorCode::Timeout, false),
        nic::EthtoolFailure::OutputTooLarge { .. } => (MonitorErrorCode::OutputLimit, false),
        nic::EthtoolFailure::InvalidOutput => (MonitorErrorCode::SchemaMismatch, false),
        nic::EthtoolFailure::ExitFailure { detail, .. }
            if detail
                .to_ascii_lowercase()
                .contains("operation not permitted")
                || detail.to_ascii_lowercase().contains("permission denied") =>
        {
            (MonitorErrorCode::PermissionDenied, false)
        }
        nic::EthtoolFailure::ExitFailure { .. } | nic::EthtoolFailure::Io { .. } => {
            (MonitorErrorCode::Io, false)
        }
    }
}

#[derive(Debug, Default)]
struct ValidatedSampleCache {
    previous: Option<ProviderSample>,
}

impl ValidatedSampleCache {
    fn build(
        &mut self,
        provider: &str,
        finished_at: Duration,
        collection_duration: Duration,
        health: ProviderHealth,
        readings: Vec<SampleReading>,
    ) -> Result<ProviderSample, MonitorValidationError> {
        let provider = provider_id(provider);
        let sample = match &self.previous {
            Some(previous) => {
                previous.refresh(provider, finished_at, collection_duration, health, readings)
            }
            None => {
                ProviderSample::new(provider, finished_at, collection_duration, health, readings)
            }
        }?;
        self.previous = Some(sample.clone());
        Ok(sample)
    }

    fn sample(
        &mut self,
        provider: &str,
        finished_at: Duration,
        collection_duration: Duration,
        health: ProviderHealth,
        readings: Vec<SampleReading>,
    ) -> ProviderSample {
        self.build(provider, finished_at, collection_duration, health, readings)
            .unwrap_or_else(|error| {
                error_sample(
                    provider,
                    finished_at,
                    collection_duration,
                    MonitorErrorCode::Internal,
                    error,
                )
            })
    }
}

fn provider_sample(
    provider: &str,
    finished_at: Duration,
    collection_duration: Duration,
    health: ProviderHealth,
    readings: Vec<SampleReading>,
) -> ProviderSample {
    ProviderSample::new(
        provider_id(provider),
        finished_at,
        collection_duration,
        health,
        readings,
    )
    .unwrap_or_else(|error| {
        error_sample(
            provider,
            finished_at,
            collection_duration,
            MonitorErrorCode::Internal,
            error,
        )
    })
}

fn translated_labels(
    descriptor: &MetricDescriptor,
    sample: &MetricSample,
) -> Result<MetricLabels, MonitorValidationError> {
    let labels = [
        ("interface", MetricLabel::Interface),
        ("ifindex", MetricLabel::Ifindex),
        ("cpu", MetricLabel::Cpu),
        ("interrupt_class", MetricLabel::InterruptClass),
    ]
    .into_iter()
    .filter(|(_, label)| descriptor.allowed_labels.contains(label))
    .filter_map(|(raw, label)| {
        sample
            .key
            .labels
            .get(raw)
            .cloned()
            .map(|value| (label, value))
    });
    MetricLabels::new(labels)
}

fn counter_bits(sample: &MetricSample) -> Option<CounterBits> {
    match sample.key.labels.get("counter_bits").map(String::as_str) {
        Some("32") => Some(CounterBits::Bits32),
        Some("64") => Some(CounterBits::Bits64),
        _ => None,
    }
}

fn add_unsupported_samples(samples: &mut Vec<ProviderSample>, session_start: Instant) {
    let implemented: BTreeSet<_> = IMPLEMENTED_PROVIDERS.into_iter().collect();
    let mut unsupported = BTreeSet::new();
    for descriptor in metric_catalog() {
        for source in descriptor.sources {
            if !implemented.contains(source.provider) {
                unsupported.insert(source.provider);
            }
        }
    }

    let finished_at = Instant::now().saturating_duration_since(session_start);
    for provider in unsupported {
        let reason = monitor_error(
            MonitorErrorCode::Unsupported,
            "provider adapter is not implemented",
        );
        samples.push(
            ProviderSample::new(
                provider_id(provider),
                finished_at,
                Duration::ZERO,
                ProviderHealth::Unsupported { reason },
                Vec::new(),
            )
            .expect("unsupported provider samples satisfy the monitor contract"),
        );
    }
}

fn provider_id(provider: &str) -> ProviderId {
    ProviderId::new(provider).expect("built-in provider IDs are valid")
}

fn error_sample(
    provider: &str,
    finished_at: Duration,
    collection_duration: Duration,
    code: MonitorErrorCode,
    diagnostic: impl fmt::Display,
) -> ProviderSample {
    let error = monitor_error(code, diagnostic);
    let health = match code {
        MonitorErrorCode::Unsupported => ProviderHealth::Unsupported { reason: error },
        MonitorErrorCode::PermissionDenied => ProviderHealth::PermissionDenied { reason: error },
        _ => ProviderHealth::Error { error },
    };
    ProviderSample::new(
        provider_id(provider),
        finished_at,
        collection_duration,
        health,
        Vec::new(),
    )
    .expect("error provider samples satisfy the monitor contract")
}

fn monitor_error(code: MonitorErrorCode, diagnostic: impl fmt::Display) -> MonitorError {
    let mut bounded = diagnostic
        .to_string()
        .bytes()
        .map(|byte| {
            if (0x20..=0x7e).contains(&byte) {
                char::from(byte)
            } else {
                '?'
            }
        })
        .take(super::model::MAX_DIAGNOSTIC_BYTES)
        .collect::<String>();
    if bounded.is_empty() {
        bounded.push_str("collector failed without a diagnostic");
    }
    MonitorError::new(code, bounded).expect("sanitized diagnostics satisfy the monitor contract")
}

struct AttemptError {
    code: MonitorErrorCode,
    message: String,
}

impl AttemptError {
    fn internal(diagnostic: impl fmt::Display) -> Self {
        Self {
            code: MonitorErrorCode::Internal,
            message: diagnostic.to_string(),
        }
    }

    fn proc(error: anyhow::Error) -> Self {
        let code = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .map_or(MonitorErrorCode::Parse, io_error_code);
        Self {
            code,
            message: error.to_string(),
        }
    }

    fn rtnetlink(error: rtnetlink::CollectError) -> Self {
        let code = if error.parse_errors() != 0 {
            MonitorErrorCode::Parse
        } else {
            MonitorErrorCode::Io
        };
        Self {
            code,
            message: error.to_string(),
        }
    }

    fn sysfs(error: sysfs::CollectError) -> Self {
        let code = if error.parse_errors() != 0 {
            MonitorErrorCode::Parse
        } else {
            MonitorErrorCode::Io
        };
        Self {
            code,
            message: error.to_string(),
        }
    }

    fn proc_net_dev(error: procfs::NetDevCollectError) -> Self {
        let code = if error.parse_errors() != 0 {
            MonitorErrorCode::Parse
        } else {
            MonitorErrorCode::Io
        };
        Self {
            code,
            message: error.to_string(),
        }
    }

    fn irq(error: irq::CollectError) -> Self {
        let kind = error.kind();
        debug_assert_eq!(
            error.parse_errors(),
            u64::from(matches!(kind, irq::CollectErrorKind::Parse))
        );
        let code = match kind {
            irq::CollectErrorKind::Io(kind) => io_error_kind_code(kind),
            irq::CollectErrorKind::Parse => MonitorErrorCode::Parse,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }

    fn tc(error: tc::CollectError) -> Self {
        let message = error.to_string();
        let code = match error.kind() {
            tc::CollectErrorKind::Unsupported => MonitorErrorCode::Unsupported,
            tc::CollectErrorKind::InvalidRequest => MonitorErrorCode::Internal,
            tc::CollectErrorKind::PermissionDenied => MonitorErrorCode::PermissionDenied,
            tc::CollectErrorKind::NotFound => MonitorErrorCode::NotFound,
            tc::CollectErrorKind::Io => MonitorErrorCode::Io,
            tc::CollectErrorKind::Timeout => MonitorErrorCode::Timeout,
            tc::CollectErrorKind::OutputLimit => MonitorErrorCode::OutputLimit,
            tc::CollectErrorKind::CardinalityLimit => MonitorErrorCode::CardinalityLimit,
            tc::CollectErrorKind::SchemaMismatch => MonitorErrorCode::SchemaMismatch,
            tc::CollectErrorKind::CommandFailed
                if message.to_ascii_lowercase().contains("permission denied")
                    || message
                        .to_ascii_lowercase()
                        .contains("operation not permitted") =>
            {
                MonitorErrorCode::PermissionDenied
            }
            tc::CollectErrorKind::CommandFailed => MonitorErrorCode::Io,
        };
        Self { code, message }
    }

    fn netfilter(error: netfilter::CollectError) -> Self {
        let message = error.to_string();
        let code = match error.kind() {
            netfilter::CollectErrorKind::NotFound => MonitorErrorCode::Unsupported,
            netfilter::CollectErrorKind::PermissionDenied => MonitorErrorCode::PermissionDenied,
            netfilter::CollectErrorKind::Io | netfilter::CollectErrorKind::CommandFailed => {
                MonitorErrorCode::Io
            }
            netfilter::CollectErrorKind::Timeout => MonitorErrorCode::Timeout,
            netfilter::CollectErrorKind::OutputLimit => MonitorErrorCode::OutputLimit,
            netfilter::CollectErrorKind::CardinalityLimit => MonitorErrorCode::CardinalityLimit,
            netfilter::CollectErrorKind::SchemaMismatch => MonitorErrorCode::SchemaMismatch,
        };
        Self { code, message }
    }
}

fn io_error_code(error: &std::io::Error) -> MonitorErrorCode {
    io_error_kind_code(error.kind())
}

fn io_error_kind_code(kind: std::io::ErrorKind) -> MonitorErrorCode {
    match kind {
        std::io::ErrorKind::PermissionDenied => MonitorErrorCode::PermissionDenied,
        std::io::ErrorKind::NotFound => MonitorErrorCode::NotFound,
        _ => MonitorErrorCode::Io,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use crate::model::MetricKey;
    use crate::monitor::{descriptor, MetricUnit};
    use tempfile::tempdir;

    use super::super::model::ReadingOutcome;
    use super::*;
    use crate::monitor::session::MonitorCollector;

    #[test]
    fn page_scope_collects_only_dependencies_and_leaves_expired_caches_untouched() {
        let root = tempdir().unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        });
        for cache in [
            &mut collector.tc_cache,
            &mut collector.netfilter_cache,
            &mut collector.nic_cache,
            &mut collector.hardirq_cache,
        ] {
            cache.record(Duration::ZERO, Vec::new());
        }
        let start = Instant::now() - Duration::from_secs(60);
        for (focus, expected) in [
            (
                MonitorSection::Socket.into(),
                vec![
                    PROC_SNMP,
                    PROC_NETSTAT,
                    PROC_SNMP6,
                    PROC_SOCKSTAT,
                    PROC_SOCKSTAT6,
                    PROC_SYS_NET_CORE,
                    PROC_SYS_NET_IPV4,
                ],
            ),
            (
                CollectionFocus::Transport,
                vec![PROC_SNMP, PROC_NETSTAT, PROC_SNMP6],
            ),
            (
                CollectionFocus::Network,
                vec![PROC_SNMP, PROC_NETSTAT, PROC_SNMP6],
            ),
            (
                CollectionFocus::Route,
                vec![PROC_SNMP, PROC_NETSTAT, PROC_SNMP6],
            ),
            (CollectionFocus::ConntrackFlows, vec![PROC_CONNTRACK]),
            (
                MonitorSection::Softirq.into(),
                vec![
                    PROC_SOFTNET,
                    PROC_SOFTIRQS,
                    PROC_SYS_NET_CORE,
                    PROC_SYS_NET_IPV4,
                ],
            ),
        ] {
            collector.set_focus(focus);
            let samples = collector.collect(start);
            assert!(samples
                .iter()
                .all(|sample| focus.allows_provider(sample.provider().as_str())));
            assert_eq!(
                samples
                    .iter()
                    .map(|sample| sample.provider().as_str())
                    .collect::<BTreeSet<_>>(),
                expected.into_iter().collect::<BTreeSet<_>>(),
                "{focus:?}"
            );
            for cache in [
                &collector.tc_cache,
                &collector.netfilter_cache,
                &collector.nic_cache,
                &collector.hardirq_cache,
            ] {
                assert_eq!(cache.collected_at, Some(Duration::ZERO));
            }
        }
        collector.set_focus(MonitorSection::Hardirq.into());
        let samples = collector.collect(start);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].provider().as_str(), PROC_INTERRUPTS);
        assert!(collector.hardirq_cache.collected_at.unwrap() >= Duration::from_secs(60));
    }

    #[test]
    fn resuming_overview_invalidates_counter_caches_but_keeps_configuration() {
        let root = tempdir().unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        });
        for cache in [
            &mut collector.tc_cache,
            &mut collector.netfilter_cache,
            &mut collector.nic_cache,
            &mut collector.hardirq_cache,
            &mut collector.config_cache,
        ] {
            cache.record(Duration::from_secs(1), Vec::new());
        }
        collector.set_focus(MonitorSection::Socket.into());
        collector.set_focus(MonitorSection::Overview.into());
        for cache in [
            &collector.tc_cache,
            &collector.netfilter_cache,
            &collector.nic_cache,
            &collector.hardirq_cache,
        ] {
            assert!(cache.refresh_due(Duration::from_secs(2), false, Duration::from_secs(10)));
            assert_eq!(cache.collected_at, None);
        }
        assert_eq!(
            collector.config_cache.collected_at,
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn cached_provider_schedule_keeps_timestamps_and_promotes_foreground() {
        let mut cache = CachedSamples::default();
        assert!(cache.refresh_due(Duration::ZERO, false, RULES_REFRESH_INTERVAL));
        let sample = error_sample(
            TC_JSON,
            Duration::from_secs(1),
            Duration::from_millis(20),
            MonitorErrorCode::Io,
            "failed probe",
        );
        cache.record(Duration::from_secs(1), vec![sample.clone()]);
        assert!(!cache.refresh_due(Duration::from_secs(10), false, RULES_REFRESH_INTERVAL));
        assert!(cache.refresh_due(Duration::from_secs(11), false, RULES_REFRESH_INTERVAL));
        assert!(cache.refresh_due(Duration::from_secs(2), true, RULES_REFRESH_INTERVAL));
        assert_eq!(cache.samples, vec![sample]);
    }

    #[test]
    fn borrowed_softnet_preserves_observations_and_recovers_after_parse_failure() {
        let root = tempdir().unwrap();
        let path = root.path().join("softnet_stat");
        let online = root.path().join("online");
        fs::write(&online, "2\n").unwrap();
        let mut context = procfs::SoftnetContext::default();
        let mut caches = BTreeMap::new();
        let started = Instant::now() - Duration::from_secs(1);
        let collect = |context: &mut procfs::SoftnetContext, caches: &mut BTreeMap<_, _>| {
            collect_attempt(started, PROC_SOFTNET, caches, || {
                context.collect(&path, &online).map_err(AttemptError::proc)
            })
        };
        let mut retained = Vec::new();
        for value in [1, 2, 4] {
            if value == 4 {
                fs::write(&path, "invalid\n").unwrap();
                let failed = collect(&mut context, &mut caches);
                let reference =
                    collect_attempt(started, PROC_SOFTNET, &mut BTreeMap::new(), || {
                        procfs::collect_softnet(&path, &online).map_err(AttemptError::proc)
                    });
                assert_eq!(failed.health(), reference.health());
                assert!(failed.readings().is_empty());
                fs::write(&online, "7\n").unwrap();
            }
            fs::write(&path, format!("{value:08x} {}\n", "00000000 ".repeat(10))).unwrap();
            let sample = collect(&mut context, &mut caches);
            let reference = ProviderSample::new(
                provider_id(PROC_SOFTNET),
                sample.finished_at(),
                sample.collection_duration(),
                ProviderHealth::Fresh,
                translate_metrics(
                    PROC_SOFTNET,
                    procfs::collect_softnet(&path, &online).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(sample, reference);
            if let Some((previous, _)) = retained.last() {
                assert!(sample.finished_at() > ProviderSample::finished_at(previous));
            }
            retained.push((sample, reference));
        }
        for (sample, reference) in retained {
            assert_eq!(sample, reference);
        }
    }

    #[test]
    fn indexed_source_lookup_matches_catalog_order_and_wildcards() {
        for metric in metric_catalog() {
            for source in metric.sources {
                for name in [
                    source.raw_metric.to_owned(),
                    source.raw_metric.replace(".*", ".counter"),
                    "missing_field".to_owned(),
                ] {
                    let expected = metric_catalog().iter().find(|descriptor| {
                        descriptor.sources.iter().any(|candidate| {
                            candidate.provider == source.provider
                                && (candidate.raw_metric == name
                                    || candidate
                                        .raw_metric
                                        .strip_suffix(".*")
                                        .is_some_and(|prefix| name.starts_with(prefix)))
                        })
                    });
                    assert_eq!(descriptor_for_source(source.provider, &name), expected);
                }
            }
        }
    }

    #[test]
    fn overview_reuses_heavy_providers_and_focus_refreshes_only_its_group() {
        let root = tempdir().unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        });
        let start = Instant::now() - Duration::from_secs(1);
        let at = start.elapsed();
        let mut expected = Vec::new();
        for (cache, providers) in [
            (&mut collector.tc_cache, vec![TC_JSON]),
            (
                &mut collector.netfilter_cache,
                vec![NFT_RULESET, IPTABLES_IPV4, IPTABLES_IPV6],
            ),
            (
                &mut collector.nic_cache,
                vec![SYSFS_NIC, ETHTOOL_TEXT, ETHTOOL_LINK_TEXT],
            ),
            (&mut collector.hardirq_cache, vec![PROC_INTERRUPTS]),
            (
                &mut collector.config_cache,
                vec![PROC_SYS_NET_CORE, PROC_SYS_NET_IPV4],
            ),
        ] {
            let samples: Vec<_> = providers
                .into_iter()
                .map(|provider| {
                    error_sample(
                        provider,
                        at,
                        Duration::ZERO,
                        MonitorErrorCode::Io,
                        "cached test probe",
                    )
                })
                .collect();
            expected.extend(samples.iter().cloned());
            cache.record(at, samples);
        }
        let background = collector.collect(start);
        for sample in &expected {
            if sample.provider().as_str() == TC_JSON {
                assert!(
                    !background.contains(sample),
                    "Overview must refresh TC each sample"
                );
                continue;
            }
            assert!(
                background.contains(sample),
                "{} was resampled",
                sample.provider().as_str()
            );
        }
        collector.focus = MonitorSection::Hardirq.into();
        let focused = collector.collect(start);
        for sample in &expected {
            assert!(
                !focused.contains(sample),
                "inactive providers must be absent, including cached samples"
            );
        }
        let refreshed = focused
            .iter()
            .find(|sample| sample.provider().as_str() == PROC_INTERRUPTS)
            .unwrap();
        assert!(refreshed.finished_at() > at);
    }

    fn nic_interface(interface: &str, ifindex: u32, setting_value: &str) -> nic::NicInterface {
        nic::NicInterface {
            interface: interface.to_owned(),
            ifindex,
            hardware_backed: true,
            operstate: nic::OperState::Up,
            sysfs: nic::NicSysfsInfo::default(),
            channels: Vec::new(),
            fallback_settings: Vec::new(),
            settings: nic::EthtoolSettingsOutcome::Collected(nic::EthtoolSettings {
                fields: vec![nic::EthtoolSetting {
                    name: "Ring RX".to_owned(),
                    value: setting_value.to_owned(),
                }],
            }),
            ethtool: nic::EthtoolOutcome::Collected(nic::NicStatistics::default()),
        }
    }

    fn translate_nic_collection(
        collection: nic::NicCollection,
        finished_at: Duration,
        collection_duration: Duration,
    ) -> Vec<ProviderSample> {
        let timing = NicCollectionTiming {
            finished_at,
            collection_duration,
        };
        let settings = translate_nic_settings(&collection, timing);
        super::translate_nic_collection(
            &collection,
            timing,
            settings,
            &mut NicReadingsCache::default(),
        )
    }

    fn nic_settings_sample(samples: &[ProviderSample]) -> &ProviderSample {
        samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap()
    }

    fn nic_dynamic_samples(
        cache: &mut NicReadingsCache,
        collection: &nic::NicCollection,
        second: u64,
    ) -> Vec<ProviderSample> {
        let timing = NicCollectionTiming {
            finished_at: Duration::from_secs(second),
            collection_duration: Duration::from_millis(5),
        };
        super::translate_nic_collection(
            collection,
            timing,
            translate_nic_settings(collection, timing),
            cache,
        )
    }

    fn nic_statistics(fields: &[(&str, u64)]) -> nic::NicStatistics {
        nic::NicStatistics {
            standard: Vec::new(),
            private: fields
                .iter()
                .map(|(name, value)| nic::PrivateNicStatistic {
                    name: (*name).to_owned(),
                    value: *value,
                    semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
                })
                .collect(),
        }
    }

    #[test]
    fn nic_readings_cache_shares_identities_but_observes_new_values() {
        let mut cache = NicReadingsCache::default();
        let mut interface = nic_interface("eth0", 2, "512");
        interface.sysfs.driver = Some("test_driver".to_owned());
        interface.ethtool = nic::EthtoolOutcome::Collected(nic::NicStatistics {
            standard: Vec::new(),
            private: (0..MAX_READINGS_PER_PROVIDER - 1)
                .map(|index| nic::PrivateNicStatistic {
                    name: format!("field_{index:04}"),
                    value: index as u64,
                    semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
                })
                .collect(),
        });
        let mut collection = nic::NicCollection {
            interfaces: vec![interface],
            errors: Vec::new(),
        };
        let before = nic_dynamic_samples(&mut cache, &collection, 1);
        let interface = &mut collection.interfaces[0];
        interface.operstate = nic::OperState::Down;
        interface.sysfs.driver = None;
        let nic::EthtoolOutcome::Collected(statistics) = &mut interface.ethtool else {
            unreachable!();
        };
        for statistic in &mut statistics.private {
            statistic.value += 100;
        }
        let after = nic_dynamic_samples(&mut cache, &collection, 2);
        assert_eq!(
            after,
            nic_dynamic_samples(&mut NicReadingsCache::default(), &collection, 2)
        );
        for provider in [SYSFS_NIC, ETHTOOL_TEXT] {
            let old = before
                .iter()
                .find(|sample| sample.provider().as_str() == provider)
                .unwrap();
            let new = after
                .iter()
                .find(|sample| sample.provider().as_str() == provider)
                .unwrap();
            assert_eq!(old.readings().len(), new.readings().len());
            for (old, new) in old.readings().iter().zip(new.readings()) {
                assert_eq!(old.labels(), new.labels());
                assert!(std::ptr::eq(old.metric().as_str(), new.metric().as_str()));
                for ((old_key, old_label), (new_key, new_label)) in
                    old.labels().iter().zip(new.labels().iter())
                {
                    assert_eq!(old_key, new_key);
                    assert!(std::ptr::eq(old_label, new_label));
                }
                if let ReadingOutcome::Observed(MetricReading::Gauge(value)) = old.outcome() {
                    assert_eq!(
                        new.outcome(),
                        &ReadingOutcome::Observed(MetricReading::Gauge(value + 100))
                    );
                }
            }
        }
        assert_eq!(before[2].readings().len(), MAX_READINGS_PER_PROVIDER);
        assert_eq!(before[2].finished_at(), Duration::from_secs(1));
        assert_eq!(after[2].finished_at(), Duration::from_secs(2));
    }

    #[test]
    fn nic_readings_cache_detects_same_count_schema_changes_and_invalid_names() {
        let mut cache = NicReadingsCache::default();
        let mut collection = nic::NicCollection {
            interfaces: vec![nic_interface("eth0", 2, "512")],
            errors: Vec::new(),
        };
        for (index, fields) in [
            [("alpha", 1), ("beta", 2), ("bad\nname", 3)],
            [("beta", 20), ("gamma", 30), ("bad\nname", 40)],
            [("gamma", 300), ("beta", 200), ("recovered", 400)],
            [("gamma", 3000), ("gamma", 2000), ("recovered", 4000)],
            [("alpha", 100), ("beta", 200), ("recovered", 300)],
        ]
        .into_iter()
        .enumerate()
        {
            let mut statistics = nic_statistics(&fields);
            statistics.standard.push(nic::StandardNicStatistic {
                statistic: if index == 0 {
                    nic::StandardStatistic::RxPackets
                } else {
                    nic::StandardStatistic::TxBytes
                },
                value: index as u64,
                semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
            });
            collection.interfaces[0].ethtool = nic::EthtoolOutcome::Collected(statistics);
            let samples = nic_dynamic_samples(&mut cache, &collection, index as u64 + 1);
            assert_eq!(
                samples,
                nic_dynamic_samples(
                    &mut NicReadingsCache::default(),
                    &collection,
                    index as u64 + 1
                )
            );
            if index == 1 {
                let fields: Vec<_> = samples[2]
                    .readings()
                    .iter()
                    .filter_map(|reading| {
                        reading
                            .labels()
                            .get(MetricLabel::Statistic)
                            .map(|name| (name, reading.outcome()))
                    })
                    .collect();
                assert_eq!(
                    fields,
                    [
                        ("beta", &ReadingOutcome::Observed(MetricReading::Gauge(20))),
                        ("gamma", &ReadingOutcome::Observed(MetricReading::Gauge(30))),
                        (
                            "tx_bytes",
                            &ReadingOutcome::Observed(MetricReading::Gauge(1))
                        ),
                    ]
                );
            }
        }
        collection.interfaces[0].ethtool =
            nic::EthtoolOutcome::Collected(nic_statistics(&[("smaller", 1)]));
        assert_eq!(
            nic_dynamic_samples(&mut cache, &collection, 6),
            nic_dynamic_samples(&mut NicReadingsCache::default(), &collection, 6)
        );
    }

    #[test]
    fn nic_readings_cache_retires_removed_or_replaced_interface_identities() {
        let mut cache = NicReadingsCache::default();
        let mut interface = nic_interface("eth0", 2, "512");
        interface.ethtool = nic::EthtoolOutcome::Collected(nic_statistics(&[("vendor", 1)]));
        let mut collection = nic::NicCollection {
            interfaces: vec![interface],
            errors: Vec::new(),
        };
        let original = nic_dynamic_samples(&mut cache, &collection, 1);
        nic_dynamic_samples(&mut cache, &nic::NicCollection::default(), 2);
        assert!(cache.interfaces.is_empty());
        let recreated = nic_dynamic_samples(&mut cache, &collection, 3);
        assert!(!std::ptr::eq(
            original[2].readings()[0]
                .labels()
                .get(MetricLabel::Interface)
                .unwrap(),
            recreated[2].readings()[0]
                .labels()
                .get(MetricLabel::Interface)
                .unwrap()
        ));
        for (second, name, ifindex, hardware_backed) in [
            (4, "eth0", 9, true),
            (5, "renamed0", 9, true),
            (6, "renamed0", 9, false),
            (7, "renamed0", 9, true),
        ] {
            let interface = &mut collection.interfaces[0];
            interface.interface = name.to_owned();
            interface.ifindex = ifindex;
            interface.hardware_backed = hardware_backed;
            interface.ethtool = if hardware_backed {
                nic::EthtoolOutcome::Collected(nic_statistics(&[("new_vendor", second)]))
            } else {
                nic::EthtoolOutcome::NotHardwareInterface
            };
            let samples = nic_dynamic_samples(&mut cache, &collection, second);
            assert_eq!(
                samples,
                nic_dynamic_samples(&mut NicReadingsCache::default(), &collection, second)
            );
            assert_eq!(cache.interfaces.len(), 1);
            assert!(samples[0].readings().iter().all(|reading| reading
                .labels()
                .get(MetricLabel::Interface)
                == Some(name)
                && reading.labels().get(MetricLabel::Ifindex) == Some("9")));
        }
    }

    #[test]
    fn nic_readings_cache_preserves_fair_budget_and_current_partial_failures() {
        let mut cache = NicReadingsCache::default();
        let large = nic::NicStatistics {
            standard: Vec::new(),
            private: (0..MAX_READINGS_PER_PROVIDER)
                .map(|index| nic::PrivateNicStatistic {
                    name: format!("field_{index:04}"),
                    value: index as u64,
                    semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
                })
                .collect(),
        };
        let mut interfaces: Vec<_> = (0..4)
            .map(|index| nic_interface(&format!("eth{index}"), index + 2, "512"))
            .collect();
        interfaces[0].ethtool = nic::EthtoolOutcome::Collected(large.clone());
        interfaces[1].ethtool = nic::EthtoolOutcome::Collected(nic_statistics(&[("small", 17)]));
        interfaces[2].ethtool = nic::EthtoolOutcome::Failed(nic::EthtoolFailure::TimedOut);
        interfaces[3].ethtool = nic::EthtoolOutcome::Partial {
            statistics: large,
            rejected_lines: 3,
            omitted_private: 4,
        };
        let mut collection = nic::NicCollection {
            interfaces,
            errors: Vec::new(),
        };
        nic_dynamic_samples(&mut cache, &collection, 1);
        collection.interfaces[0].ethtool =
            nic::EthtoolOutcome::Failed(nic::EthtoolFailure::PermissionDenied {
                detail: "denied".to_owned(),
            });
        collection.interfaces[2].ethtool =
            nic::EthtoolOutcome::Collected(nic_statistics(&[("recovered", 23)]));
        let nic::EthtoolOutcome::Partial {
            statistics,
            rejected_lines,
            ..
        } = &mut collection.interfaces[3].ethtool
        else {
            unreachable!()
        };
        statistics.private[0].name = "replacement".to_owned();
        statistics.private[0].value = 99;
        *rejected_lines = 7;
        let samples = nic_dynamic_samples(&mut cache, &collection, 2);
        assert_eq!(
            samples,
            nic_dynamic_samples(&mut NicReadingsCache::default(), &collection, 2)
        );
        let stats = &samples[2];
        assert_eq!(stats.readings().len(), MAX_READINGS_PER_PROVIDER);
        assert!(
            matches!(stats.health(), ProviderHealth::Partial { warning } if warning.code() == MonitorErrorCode::CardinalityLimit && warning.diagnostic().contains("schema partials 1") && warning.diagnostic().contains("rejected=7"))
        );
        for name in ["small", "recovered", "replacement"] {
            assert!(stats
                .readings()
                .iter()
                .any(|reading| reading.labels().get(MetricLabel::Statistic) == Some(name)));
        }
        assert!(!stats.readings().iter().any(|reading| reading
            .labels()
            .get(MetricLabel::Interface)
            == Some("eth0")
            && reading.labels().get(MetricLabel::Statistic).is_some()));
        assert_eq!(
            stats
                .readings()
                .iter()
                .filter(|reading| reading.metric().as_str()
                    == super::super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID)
                .count(),
            4
        );
    }

    #[test]
    fn nic_settings_cache_refreshes_first_and_at_thirty_seconds() {
        let mut cache = NicSettingsCache::default();
        assert!(cache.refresh_due(Duration::ZERO));

        let initial = nic::NicCollection {
            interfaces: vec![nic_interface("eth0", 2, "512")],
            errors: Vec::new(),
        };
        cache.collect_samples(
            Duration::ZERO,
            &mut NicReadingsCache::default(),
            |include_settings| {
                assert!(include_settings);
                (
                    initial.clone(),
                    NicCollectionTiming {
                        finished_at: Duration::from_secs(1),
                        collection_duration: Duration::from_millis(20),
                    },
                )
            },
        );

        assert!(!cache.refresh_due(Duration::from_secs(30)));
        assert!(cache.refresh_due(Duration::from_secs(31)));
    }

    #[test]
    fn nic_settings_cache_shares_immutable_readings_during_dynamic_cycles() {
        let mut cache = NicSettingsCache::default();
        let mut initial = nic::NicCollection {
            interfaces: vec![nic_interface("eth0", 2, "512")],
            errors: Vec::new(),
        };
        cache.record(
            &initial,
            NicCollectionTiming {
                finished_at: Duration::from_secs(1),
                collection_duration: Duration::from_millis(20),
            },
        );
        let cached = cache.sample.as_ref().unwrap().clone();
        let original_readings = cached.readings().to_vec();
        initial.interfaces[0] = nic_interface("eth0", 2, "1024");
        for second in 2..=30 {
            let samples = cache.collect_samples(
                Duration::from_secs(second),
                &mut NicReadingsCache::default(),
                |include_settings| {
                    assert!(!include_settings);
                    let mut dynamic = initial.clone();
                    dynamic.interfaces[0].settings = nic::EthtoolSettingsOutcome::RefreshPending;
                    dynamic.interfaces[0].operstate = nic::OperState::Down;
                    (
                        dynamic,
                        NicCollectionTiming {
                            finished_at: Duration::from_secs(second),
                            collection_duration: Duration::from_millis(5),
                        },
                    )
                },
            );
            let settings = nic_settings_sample(&samples);
            assert_eq!(settings, &cached);
            assert!(std::ptr::eq(settings.readings(), cached.readings()));
            assert!(samples[0].readings().iter().any(|reading| {
                reading.metric().as_str() == "linux.nic.link_state"
                    && matches!(reading.outcome(), ReadingOutcome::Observed(MetricReading::State(value)) if value.as_str() == "down")
            }));
        }

        let refreshed = cache.collect_samples(
            Duration::from_secs(31),
            &mut NicReadingsCache::default(),
            |include_settings| {
                assert!(include_settings);
                (
                    initial.clone(),
                    NicCollectionTiming {
                        finished_at: Duration::from_secs(31),
                        collection_duration: Duration::from_millis(25),
                    },
                )
            },
        );
        assert_ne!(
            nic_settings_sample(&refreshed).readings(),
            cached.readings()
        );
        assert_eq!(cached.readings(), original_readings);
        assert_eq!(cached.finished_at(), Duration::from_secs(1));
        assert_eq!(cached.collection_duration(), Duration::from_millis(20));
        assert!(!cache.refresh_due(Duration::from_secs(60)));
        assert!(cache.refresh_due(Duration::from_secs(61)));
    }

    #[test]
    fn nic_settings_cache_requests_immediate_refresh_for_identity_changes() {
        let mut virtual_interface = nic_interface("eth0", 2, "");
        virtual_interface.hardware_backed = false;
        virtual_interface.settings = nic::EthtoolSettingsOutcome::NotHardwareInterface;
        virtual_interface.ethtool = nic::EthtoolOutcome::NotHardwareInterface;
        for interfaces in [
            vec![nic_interface("eth0", 9, "1024")],
            vec![nic_interface("renamed0", 2, "1024")],
            vec![
                nic_interface("eth0", 2, "512"),
                nic_interface("eth1", 3, "1024"),
            ],
            vec![virtual_interface],
            Vec::new(),
        ] {
            let mut cache = NicSettingsCache::default();
            cache.record(
                &nic::NicCollection {
                    interfaces: vec![nic_interface("eth0", 2, "512")],
                    errors: Vec::new(),
                },
                NicCollectionTiming {
                    finished_at: Duration::from_secs(1),
                    collection_duration: Duration::from_millis(20),
                },
            );
            let changed = nic::NicCollection {
                interfaces,
                errors: Vec::new(),
            };
            let mut attempts = Vec::new();
            let timing = NicCollectionTiming {
                finished_at: Duration::from_secs(3),
                collection_duration: Duration::from_millis(25),
            };
            let samples = cache.collect_samples(
                Duration::from_secs(2),
                &mut NicReadingsCache::default(),
                |include_settings| {
                    attempts.push(include_settings);
                    let mut collection = changed.clone();
                    if !include_settings {
                        for interface in &mut collection.interfaces {
                            if interface.hardware_backed {
                                interface.settings = nic::EthtoolSettingsOutcome::RefreshPending;
                            }
                        }
                    }
                    (collection, timing)
                },
            );
            assert_eq!(attempts, [false, true]);
            assert_eq!(
                nic_settings_sample(&samples),
                &translate_nic_settings(&changed, timing)
            );
            assert!(cache.matches_inventory(&changed));
            assert!(!cache.refresh_due(Duration::from_secs(32)));
            assert!(cache.refresh_due(Duration::from_secs(33)));
        }
    }

    #[test]
    fn cached_settings_keep_the_actual_refresh_time_and_cost() {
        let collection = nic::NicCollection {
            interfaces: vec![nic_interface("eth0", 2, "512")],
            errors: Vec::new(),
        };
        let mut cache = NicSettingsCache::default();
        cache.record(
            &collection,
            NicCollectionTiming {
                finished_at: Duration::from_secs(2),
                collection_duration: Duration::from_millis(30),
            },
        );
        let samples = cache.collect_samples(
            Duration::from_secs(10),
            &mut NicReadingsCache::default(),
            |include_settings| {
                assert!(!include_settings);
                let mut dynamic = collection.clone();
                dynamic.interfaces[0].settings = nic::EthtoolSettingsOutcome::RefreshPending;
                (
                    dynamic,
                    NicCollectionTiming {
                        finished_at: Duration::from_secs(10),
                        collection_duration: Duration::from_millis(5),
                    },
                )
            },
        );

        for provider in [SYSFS_NIC, ETHTOOL_TEXT] {
            let sample = samples
                .iter()
                .find(|sample| sample.provider().as_str() == provider)
                .unwrap();
            assert_eq!(sample.finished_at(), Duration::from_secs(10));
            assert_eq!(sample.collection_duration(), Duration::from_millis(5));
        }
        let settings = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap();
        assert_eq!(settings.finished_at(), Duration::from_secs(2));
        assert_eq!(settings.collection_duration(), Duration::from_millis(30));
    }

    #[test]
    fn nic_settings_cache_ignores_inventory_order_including_virtual_interfaces() {
        let mut cache = NicSettingsCache::default();
        let mut collection = nic::NicCollection {
            interfaces: vec![
                nic_interface("eth0", 2, "512"),
                nic_interface("eth1", 3, "1024"),
            ],
            errors: Vec::new(),
        };
        let timing = NicCollectionTiming {
            finished_at: Duration::from_secs(1),
            collection_duration: Duration::from_millis(20),
        };
        let mut virtual_interface = nic_interface("veth0", 4, "");
        virtual_interface.hardware_backed = false;
        virtual_interface.settings = nic::EthtoolSettingsOutcome::NotHardwareInterface;
        virtual_interface.ethtool = nic::EthtoolOutcome::NotHardwareInterface;
        virtual_interface.channels = vec![nic::EthtoolSetting {
            name: "Queue source".to_owned(),
            value: "fixed".to_owned(),
        }];
        collection.interfaces.push(virtual_interface);
        cache.record(&collection, timing);
        let cached = cache.sample.as_ref().unwrap().clone();
        collection.interfaces.reverse();
        for interface in &mut collection.interfaces {
            interface.settings = nic::EthtoolSettingsOutcome::RefreshPending;
        }
        let samples = cache.collect_samples(
            Duration::from_secs(2),
            &mut NicReadingsCache::default(),
            |include_settings| {
                assert!(!include_settings);
                (collection.clone(), timing)
            },
        );
        assert!(std::ptr::eq(
            nic_settings_sample(&samples).readings(),
            cached.readings()
        ));
        assert_eq!(
            nic_settings_sample(&samples).finished_at(),
            Duration::from_secs(1)
        );
        assert!(cached.readings().iter().any(|reading| {
            reading.labels().get(MetricLabel::Interface) == Some("veth0")
                && reading.labels().get(MetricLabel::Statistic) == Some("Queue source")
                && matches!(reading.outcome(), ReadingOutcome::Observed(MetricReading::State(value)) if value.as_str() == "fixed")
        }));
        collection.interfaces.last_mut().unwrap().ifindex += 100;
        assert!(!cache.matches_inventory(&collection));
    }

    #[test]
    fn nic_settings_cache_retains_partial_health_and_per_interface_statuses() {
        let partial = nic::EthtoolSettingsOutcome::Partial {
            settings: nic::EthtoolSettings {
                fields: vec![nic::EthtoolSetting {
                    name: "Ring RX".to_owned(),
                    value: "256".to_owned(),
                }],
            },
            rejected_lines: 3,
        };
        for (outcome, status, code) in [
            (
                partial,
                "partial_schema_mismatch",
                MonitorErrorCode::SchemaMismatch,
            ),
            (
                nic::EthtoolSettingsOutcome::Failed(nic::EthtoolFailure::TimedOut),
                "timed_out",
                MonitorErrorCode::Timeout,
            ),
            (
                nic::EthtoolSettingsOutcome::Failed(nic::EthtoolFailure::Unsupported {
                    detail: "unsupported probe".to_owned(),
                }),
                "unsupported",
                MonitorErrorCode::Unsupported,
            ),
            (
                nic::EthtoolSettingsOutcome::RefreshPending,
                "refresh_pending",
                MonitorErrorCode::Internal,
            ),
        ] {
            let mut cache = NicSettingsCache::default();
            let mut collection = nic::NicCollection {
                interfaces: vec![
                    nic_interface("eth0", 2, "512"),
                    nic_interface("eth1", 3, "1024"),
                ],
                errors: Vec::new(),
            };
            let timing = NicCollectionTiming {
                finished_at: Duration::from_secs(1),
                collection_duration: Duration::from_millis(20),
            };
            cache.record(&collection, timing);
            let successful = cache.sample.as_ref().unwrap().clone();
            collection.interfaces[1].settings = outcome;
            let refreshed = cache.collect_samples(
                Duration::from_secs(31),
                &mut NicReadingsCache::default(),
                |include_settings| {
                    assert!(include_settings);
                    (
                        collection.clone(),
                        NicCollectionTiming {
                            finished_at: Duration::from_secs(31),
                            ..timing
                        },
                    )
                },
            );
            let cached = nic_settings_sample(&refreshed);
            assert!(matches!(successful.health(), ProviderHealth::Fresh));
            assert_eq!(cached.finished_at(), Duration::from_secs(31));
            assert!(
                matches!(cached.health(), ProviderHealth::Partial { warning } if warning.code() == code)
            );
            let statuses: Vec<_> = cached
                .readings()
                .iter()
                .filter(|reading| {
                    reading.metric().as_str() == super::super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID
                })
                .map(|reading| {
                    let ReadingOutcome::Observed(MetricReading::State(value)) = reading.outcome()
                    else {
                        panic!("expected observed settings status");
                    };
                    (
                        reading.labels().get(MetricLabel::Interface).unwrap(),
                        value.as_str(),
                    )
                })
                .collect();
            assert_eq!(statuses, [("eth0", "complete"), ("eth1", status)]);
            for interface in &mut collection.interfaces {
                interface.settings = nic::EthtoolSettingsOutcome::RefreshPending;
            }
            collection.errors.push(nic::NicCollectionError {
                interface: Some("eth0".to_owned()),
                kind: nic::NicCollectionErrorKind::ReadOperstate,
                detail: "dynamic sysfs failure".to_owned(),
            });
            let samples = cache.collect_samples(
                Duration::from_secs(32),
                &mut NicReadingsCache::default(),
                |include_settings| {
                    assert!(!include_settings);
                    (
                        collection.clone(),
                        NicCollectionTiming {
                            finished_at: Duration::from_secs(32),
                            ..timing
                        },
                    )
                },
            );
            assert_eq!(nic_settings_sample(&samples), cached);
            assert!(std::ptr::eq(
                nic_settings_sample(&samples).readings(),
                cached.readings()
            ));
            assert!(
                matches!(samples[0].health(), ProviderHealth::Partial { warning } if warning.code() == MonitorErrorCode::Io)
            );
        }
    }

    #[test]
    fn nic_settings_cache_drops_removed_failures_and_refreshes_reused_identity() {
        let mut cache = NicSettingsCache::default();
        let mut initial = nic::NicCollection {
            interfaces: vec![
                nic_interface("eth0", 2, "512"),
                nic_interface("eth1", 3, ""),
            ],
            errors: Vec::new(),
        };
        initial.interfaces[1].settings =
            nic::EthtoolSettingsOutcome::Failed(nic::EthtoolFailure::TimedOut);
        cache.record(
            &initial,
            NicCollectionTiming {
                finished_at: Duration::from_secs(1),
                collection_duration: Duration::from_millis(20),
            },
        );
        let mut attempts = Vec::new();
        let removed = cache.collect_samples(
            Duration::from_secs(2),
            &mut NicReadingsCache::default(),
            |include_settings| {
                attempts.push(include_settings);
                (
                    nic::NicCollection {
                        interfaces: vec![nic_interface("eth0", 2, "512")],
                        errors: Vec::new(),
                    },
                    NicCollectionTiming {
                        finished_at: Duration::from_secs(2),
                        collection_duration: Duration::from_millis(15),
                    },
                )
            },
        );
        assert_eq!(attempts, [false, true]);
        assert!(matches!(
            nic_settings_sample(&removed).health(),
            ProviderHealth::Fresh
        ));
        assert!(nic_settings_sample(&removed)
            .readings()
            .iter()
            .all(|reading| reading.labels().get(MetricLabel::Interface) == Some("eth0")));

        attempts.clear();
        initial.interfaces[1] = nic_interface("eth1", 3, "2048");
        let timing = NicCollectionTiming {
            finished_at: Duration::from_secs(3),
            collection_duration: Duration::from_millis(25),
        };
        let recreated = cache.collect_samples(
            Duration::from_secs(3),
            &mut NicReadingsCache::default(),
            |include_settings| {
                attempts.push(include_settings);
                (initial.clone(), timing)
            },
        );
        assert_eq!(attempts, [false, true]);
        assert_eq!(
            nic_settings_sample(&recreated),
            &translate_nic_settings(&initial, timing)
        );
        assert!(matches!(
            nic_settings_sample(&recreated).health(),
            ProviderHealth::Fresh
        ));
    }

    #[test]
    fn nic_settings_cache_uses_the_inventory_from_the_hotplug_retry() {
        let mut cache = NicSettingsCache::default();
        let timing = NicCollectionTiming {
            finished_at: Duration::from_secs(1),
            collection_duration: Duration::from_millis(20),
        };
        cache.record(&nic::NicCollection::default(), timing);
        let mut attempts = Vec::new();
        let refreshed = nic::NicCollection {
            interfaces: vec![nic_interface("eth1", 9, "1024")],
            errors: Vec::new(),
        };
        let refreshed_timing = NicCollectionTiming {
            finished_at: Duration::from_secs(3),
            ..timing
        };
        let samples = cache.collect_samples(
            Duration::from_secs(2),
            &mut NicReadingsCache::default(),
            |include_settings| {
                attempts.push(include_settings);
                if include_settings {
                    (refreshed.clone(), refreshed_timing)
                } else {
                    (
                        nic::NicCollection {
                            interfaces: vec![nic_interface("eth0", 2, "")],
                            errors: Vec::new(),
                        },
                        NicCollectionTiming {
                            finished_at: Duration::from_secs(2),
                            ..timing
                        },
                    )
                }
            },
        );
        assert_eq!(attempts, [false, true]);
        assert!(cache.matches_inventory(&refreshed));
        assert_eq!(
            nic_settings_sample(&samples),
            &translate_nic_settings(&refreshed, refreshed_timing)
        );
        assert!(samples
            .iter()
            .all(|sample| sample.finished_at() == refreshed_timing.finished_at));
    }

    #[test]
    fn shared_metadata_timing_extends_duration_without_moving_completion() {
        let session_start = Instant::now();
        let metadata_started = session_start + Duration::from_secs(1);
        let nic_started = session_start + Duration::from_secs(2);
        let finished = session_start + Duration::from_secs(3);
        let shared = NicCollectionTiming::observed(session_start, metadata_started, finished);
        let independent = NicCollectionTiming::observed(session_start, nic_started, finished);
        assert_eq!(shared.finished_at, independent.finished_at);
        assert_eq!(shared.finished_at, Duration::from_secs(3));
        assert_eq!(shared.collection_duration, Duration::from_secs(2));
        assert_eq!(independent.collection_duration, Duration::from_secs(1));
    }

    #[test]
    fn no_hardware_uses_current_inventory_time_and_zero_settings_cost() {
        let mut cache = NicSettingsCache::default();
        cache.record(
            &nic::NicCollection::default(),
            NicCollectionTiming {
                finished_at: Duration::from_secs(2),
                collection_duration: Duration::from_millis(30),
            },
        );
        let samples = cache.collect_samples(
            Duration::from_secs(10),
            &mut NicReadingsCache::default(),
            |include_settings| {
                assert!(!include_settings);
                (
                    nic::NicCollection::default(),
                    NicCollectionTiming {
                        finished_at: Duration::from_secs(10),
                        collection_duration: Duration::from_millis(5),
                    },
                )
            },
        );
        let settings = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap();

        assert_eq!(settings.finished_at(), Duration::from_secs(10));
        assert_eq!(settings.collection_duration(), Duration::ZERO);
        assert!(matches!(
            settings.health(),
            ProviderHealth::Unsupported { .. }
        ));
        assert!(!cache.refresh_due(Duration::from_secs(31)));
        assert!(cache.refresh_due(Duration::from_secs(32)));
    }

    #[test]
    fn pending_settings_make_the_provider_partial() {
        let mut interface = nic_interface("eth0", 2, "");
        interface.settings = nic::EthtoolSettingsOutcome::RefreshPending;
        let samples = translate_nic_collection(
            nic::NicCollection {
                interfaces: vec![interface],
                errors: Vec::new(),
            },
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let settings = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap();

        assert!(matches!(
            settings.health(),
            ProviderHealth::Partial { warning }
                if warning.code() == MonitorErrorCode::Internal
                    && warning.diagnostic().contains("pending after collection")
        ));
    }

    fn translated(provider: &str, samples: Vec<MetricSample>) -> Vec<SampleReading> {
        translate_metrics(provider, samples).unwrap()
    }

    fn canonical_translation(
        provider: &str,
        readings: Result<Vec<SampleReading>, MonitorValidationError>,
        tick: u64,
    ) -> Result<ProviderSample, MonitorValidationError> {
        readings.and_then(|readings| {
            ProviderSample::new(
                provider_id(provider),
                Duration::from_secs(tick),
                Duration::from_millis(tick),
                ProviderHealth::Fresh,
                readings,
            )
        })
    }

    fn assert_canonical_readings(readings: &[SampleReading]) {
        assert!(readings.windows(2).all(|pair| {
            (pair[0].metric(), pair[0].labels()) <= (pair[1].metric(), pair[1].labels())
        }));
    }

    fn cached_softnet_fixture() -> Vec<MetricSample> {
        [
            ("2", "dropped"),
            ("10", "backlog_len"),
            ("1", "future_field"),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (cpu, metric))| MetricSample {
            key: MetricKey::new("proc_softnet", "softnet_cpu", metric)
                .with_label("cpu", cpu)
                .with_label("counter_bits", "32"),
            value: index as u64 + 1,
        })
        .collect()
    }

    #[test]
    fn metric_templates_match_uncached_translation_after_full_schema_mutations() {
        let mut cache = MetricReadingsCache::default();
        for mutation in 0..16 {
            let mut metrics = cached_softnet_fixture();
            match mutation {
                0 | 15 => {}
                1 => metrics.iter_mut().for_each(|sample| sample.value += 100),
                2 => metrics.reverse(),
                3 => metrics[0].key.metric = "backlog_len".to_owned(),
                4 => {
                    metrics[0]
                        .key
                        .labels
                        .insert("cpu".to_owned(), "3".to_owned());
                }
                5 => metrics[2].key.metric = "processed".to_owned(),
                6 => metrics[0].key.source = "proc_net_snmp".to_owned(),
                7 => metrics[0].key.group = "softnet".to_owned(),
                8 => {
                    metrics[0].key.labels.remove("cpu");
                }
                9 => {
                    metrics[0]
                        .key
                        .labels
                        .insert("cpu".to_owned(), "invalid".to_owned());
                }
                10 => {
                    metrics[0]
                        .key
                        .labels
                        .insert("counter_bits".to_owned(), "64".to_owned());
                }
                11 => {
                    metrics[0]
                        .key
                        .labels
                        .insert("counter_bits".to_owned(), "unknown".to_owned());
                }
                12 => metrics[1] = metrics[0].clone(),
                13 => metrics.clear(),
                14 => metrics[0].value = u64::MAX,
                _ => unreachable!(),
            }
            let expected = canonical_translation(
                PROC_SOFTNET,
                translate_metrics(PROC_SOFTNET, metrics.clone()),
                mutation + 1,
            );
            let actual = cache.translate(PROC_SOFTNET, metrics);
            if let Ok(readings) = &actual {
                assert_canonical_readings(readings);
            }
            assert_eq!(
                canonical_translation(PROC_SOFTNET, actual, mutation + 1),
                expected,
                "schema mutation {mutation}"
            );
        }
        let metrics = cached_softnet_fixture();
        assert_eq!(
            cache.translate(PROC_SNMP, metrics.clone()).unwrap(),
            translate_metrics(PROC_SNMP, metrics).unwrap(),
            "changing the provider cannot reuse another source's templates"
        );

        let mut snmp = vec![MetricSample {
            key: MetricKey::new("proc_net_snmp", "Tcp", "InSegs"),
            value: 11,
        }];
        cache.translate(PROC_SNMP, snmp.clone()).unwrap();
        snmp[0].key.group = "Udp".to_owned();
        assert_eq!(
            cache.translate(PROC_SNMP, snmp.clone()),
            translate_metrics(PROC_SNMP, snmp),
            "raw group changes must redo descriptor selection"
        );
    }

    #[test]
    fn metric_templates_share_identities_but_keep_current_values_and_collection_results() {
        let mut cache = MetricReadingsCache::default();
        let mut metrics = cached_softnet_fixture();
        let before = cache.translate(PROC_SOFTNET, metrics.clone()).unwrap();
        let templates = cache.templates.as_ptr();
        metrics.iter_mut().for_each(|sample| sample.value += 100);
        let after = cache.translate(PROC_SOFTNET, metrics.clone()).unwrap();
        assert_eq!(cache.templates.as_ptr(), templates);
        for (old, new) in before.iter().zip(&after) {
            assert!(std::ptr::eq(old.metric().as_str(), new.metric().as_str()));
            assert!(std::ptr::eq(
                old.labels().get(MetricLabel::Cpu).unwrap(),
                new.labels().get(MetricLabel::Cpu).unwrap()
            ));
            assert_ne!(old.outcome(), new.outcome());
        }
        assert_eq!(
            canonical_translation(PROC_SOFTNET, Ok(after), 2),
            canonical_translation(
                PROC_SOFTNET,
                translate_metrics(PROC_SOFTNET, metrics.clone()),
                2
            )
        );
        assert_eq!(
            canonical_translation(PROC_SOFTNET, Ok(before), 1),
            canonical_translation(
                PROC_SOFTNET,
                translate_metrics(PROC_SOFTNET, cached_softnet_fixture()),
                1
            )
        );

        let mut caches = BTreeMap::new();
        let start = Instant::now() - Duration::from_secs(2);
        let first = collect_attempt(start, PROC_SOFTNET, &mut caches, || {
            Ok(cached_softnet_fixture())
        });
        let failed = collect_attempt(start, PROC_SOFTNET, &mut caches, || {
            Err::<Vec<MetricSample>, _>(AttemptError {
                code: MonitorErrorCode::Timeout,
                message: "current probe timed out".to_owned(),
            })
        });
        assert!(!failed.health().is_fresh());
        assert!(failed.readings().is_empty());
        let recovered = collect_attempt(
            start - Duration::from_secs(1),
            PROC_SOFTNET,
            &mut caches,
            || Ok(metrics),
        );
        assert!(recovered.health().is_fresh());
        assert!(recovered.finished_at() >= first.finished_at() + Duration::from_secs(1));
        assert_ne!(recovered.readings(), first.readings());
    }

    #[test]
    fn canonical_order_cache_matches_all_small_permutations_and_fresh_outcomes() {
        let base = translated(
            PROC_SOFTNET,
            vec![
                MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet_cpu", "dropped")
                        .with_label("cpu", "10"),
                    value: 1,
                },
                MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet_cpu", "processed")
                        .with_label("cpu", "2"),
                    value: 2,
                },
                MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet_cpu", "backlog_len")
                        .with_label("cpu", "2"),
                    value: 3,
                },
                MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet_cpu", "dropped")
                        .with_label("cpu", "1"),
                    value: 4,
                },
            ],
        );
        let mut cache = CanonicalReadingOrder::default();
        for encoded in 0..256_usize {
            let indices = [encoded % 4, encoded / 4 % 4, encoded / 16 % 4, encoded / 64];
            if indices.into_iter().collect::<BTreeSet<_>>().len() != 4 {
                continue;
            }
            let input = indices.map(|index| base[index].clone());
            let mut first = input.to_vec();
            cache.reorder(&mut first);
            let identities = cache.identities.as_ptr();
            let mut current = input
                .iter()
                .map(|reading| {
                    SampleReading::unavailable(
                        reading.metric().clone(),
                        reading.labels().clone(),
                        UnavailableReason::Missing,
                    )
                })
                .collect::<Vec<_>>();
            let expected = canonical_translation(PROC_SOFTNET, Ok(current.clone()), 2).unwrap();
            cache.reorder(&mut current);
            assert_eq!(cache.identities.as_ptr(), identities);
            assert_canonical_readings(&first);
            assert_canonical_readings(&current);
            assert_eq!(current, expected.readings());
            assert_eq!(
                canonical_translation(PROC_SOFTNET, Ok(first), 1),
                canonical_translation(PROC_SOFTNET, Ok(input.to_vec()), 1)
            );
        }
    }

    #[test]
    fn canonical_order_keeps_provider_kind_duplicate_and_cardinality_validation() {
        let base = translated(PROC_SOFTNET, cached_softnet_fixture());
        let mut cache = CanonicalReadingOrder::default();
        cache.reorder(&mut base.clone());
        let mut cases = vec![
            base.clone(),
            base.clone(),
            base.clone(),
            vec![base[0].clone(); MAX_READINGS_PER_PROVIDER + 1],
        ];
        cases[0][0] = SampleReading::observed(
            base[0].metric().clone(),
            base[0].labels().clone(),
            MetricReading::Gauge(99),
        );
        cases[1][1] = cases[1][0].clone();
        for (index, mut readings) in cases.into_iter().enumerate() {
            let provider = if index == 2 { PROC_SNMP } else { PROC_SOFTNET };
            let expected = canonical_translation(provider, Ok(readings.clone()), 1);
            assert!(expected.is_err());
            cache.reorder(&mut readings);
            assert_eq!(canonical_translation(provider, Ok(readings), 1), expected);
        }
        assert!(cache.identities.is_empty());
        let mut readings = base;
        cache.reorder(&mut readings);
        assert_canonical_readings(&readings);
        canonical_translation(PROC_SOFTNET, Ok(readings), 2).unwrap();
    }

    #[test]
    fn link_templates_match_uncached_translation_through_identity_and_width_changes() {
        let mut cache = LinkReadingsCache::default();
        for mutation in 0..15 {
            let mut links = vec![
                rtnetlink::LinkCounters {
                    interface: "eth10".to_owned(),
                    ifindex: 10,
                    counter_bits: 64,
                    values: (100..124).collect(),
                    carrier_changes: Some(7),
                },
                rtnetlink::LinkCounters {
                    interface: "eth2".to_owned(),
                    ifindex: 2,
                    counter_bits: 64,
                    values: (200..225).collect(),
                    carrier_changes: None,
                },
            ];
            match mutation {
                0 | 14 => {}
                1 => links.iter_mut().for_each(|link| {
                    link.values.iter_mut().for_each(|value| *value += 1000);
                    link.carrier_changes = link.carrier_changes.map(|value| value + 1);
                }),
                2 => links.reverse(),
                3 => links[0].interface = "renamed0".to_owned(),
                4 => links[0].ifindex = 77,
                5 => links[0].values.push(124),
                6 => {
                    links[0].carrier_changes = None;
                    links[0].values.push(124);
                }
                7 => links[0].counter_bits = 32,
                8 => {
                    links[0].counter_bits = 32;
                    links[0].values[0] = u64::MAX;
                }
                9 => links[0].interface = "invalid\n".to_owned(),
                10 => {
                    links[0].interface = "eth2".to_owned();
                    links[0].ifindex = 2;
                }
                11 => {
                    links.pop();
                }
                12 => links.clear(),
                13 => links[1].values.push(999),
                _ => unreachable!(),
            }
            let expected = canonical_translation(
                RTNETLINK_LINK,
                translate_link_counters(&links),
                mutation + 1,
            );
            let templates = cache.templates.as_ptr();
            let actual = cache.translate(&links);
            if mutation == 1 {
                assert_eq!(
                    cache.templates.as_ptr(),
                    templates,
                    "values do not rebuild identities"
                );
            }
            if let Ok(readings) = &actual {
                assert_canonical_readings(readings);
            }
            assert_eq!(
                canonical_translation(RTNETLINK_LINK, actual, mutation + 1),
                expected,
                "link mutation {mutation}"
            );
        }
    }

    #[test]
    fn translation_cache_limits_do_not_truncate_or_admit_invalid_samples() {
        let metrics = (0..=MAX_READINGS_PER_PROVIDER)
            .map(|cpu| MetricSample {
                key: MetricKey::new("proc_softnet", "softnet_cpu", "dropped")
                    .with_label("cpu", cpu.to_string()),
                value: cpu as u64,
            })
            .collect::<Vec<_>>();
        let mut metrics_cache = MetricReadingsCache::default();
        let expected = canonical_translation(
            PROC_SOFTNET,
            translate_metrics(PROC_SOFTNET, metrics.clone()),
            1,
        );
        assert_eq!(
            expected,
            Err(MonitorValidationError::TooManyProviderReadings)
        );
        assert_eq!(
            canonical_translation(
                PROC_SOFTNET,
                metrics_cache.translate(PROC_SOFTNET, metrics),
                1
            ),
            expected
        );
        assert!(metrics_cache.templates.is_empty());

        let links = (0..=MAX_READINGS_PER_PROVIDER / 24)
            .map(|index| rtnetlink::LinkCounters {
                interface: format!("eth{index}"),
                ifindex: index as u32 + 1,
                counter_bits: 64,
                values: vec![1; 24],
                carrier_changes: None,
            })
            .collect::<Vec<_>>();
        let mut link_cache = LinkReadingsCache::default();
        let expected = canonical_translation(RTNETLINK_LINK, translate_link_counters(&links), 1);
        assert_eq!(
            expected,
            Err(MonitorValidationError::TooManyProviderReadings)
        );
        assert_eq!(
            canonical_translation(RTNETLINK_LINK, link_cache.translate(&links), 1),
            expected
        );
        assert!(link_cache.templates.is_empty());
    }

    #[test]
    fn maps_proc_group_and_metric_through_the_catalog() {
        let readings = translated(
            PROC_SNMP,
            vec![
                MetricSample {
                    key: MetricKey::new("proc_net_snmp", "Tcp", "InSegs"),
                    value: 42,
                },
                MetricSample {
                    key: MetricKey::new("proc_net_snmp", "Tcp", "FutureField"),
                    value: 7,
                },
            ],
        );

        assert_eq!(readings.len(), 1);
        assert_eq!(
            readings[0].metric().as_str(),
            "linux.socket.tcp.segments_in"
        );
        assert!(matches!(
            readings[0].outcome(),
            ReadingOutcome::Observed(MetricReading::Counter {
                value: 42,
                bits: None
            })
        ));
    }

    #[test]
    fn maps_network_route_mibs_without_merging_ipv4_and_ipv6() {
        let snmp = translated(
            PROC_SNMP,
            vec![
                MetricSample {
                    key: MetricKey::new("proc_net_snmp", "Ip", "OutNoRoutes"),
                    value: 3,
                },
                MetricSample {
                    key: MetricKey::new("proc_net_snmp", "Icmp", "InDestUnreachs"),
                    value: 5,
                },
            ],
        );
        let netstat = translated(
            PROC_NETSTAT,
            vec![MetricSample {
                key: MetricKey::new("proc_net_netstat", "IpExt", "InOctets"),
                value: 1_024,
            }],
        );
        let snmp6 = translated(
            PROC_SNMP6,
            vec![
                MetricSample {
                    key: MetricKey::new("proc_net_snmp6", "snmp6", "Ip6OutNoRoutes"),
                    value: 7,
                },
                MetricSample {
                    key: MetricKey::new("proc_net_snmp6", "snmp6", "Icmp6InPktTooBigs"),
                    value: 11,
                },
            ],
        );

        let ids = snmp
            .iter()
            .chain(&netstat)
            .chain(&snmp6)
            .map(|reading| reading.metric().as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            ids,
            BTreeSet::from([
                "linux.socket.icmp.input_destination_unreachable",
                "linux.socket.icmpv6.input_packet_too_big",
                "linux.socket.ip.input_octets",
                "linux.socket.ip.output_no_routes",
                "linux.socket.ipv6.output_no_routes",
            ])
        );
        assert_eq!(
            descriptor("linux.socket.ip.input_octets").unwrap().unit,
            MetricUnit::Bytes
        );
    }

    #[test]
    fn typed_link_counters_match_the_generic_adapter() {
        for bits in [32, 64] {
            let links = vec![rtnetlink::LinkCounters {
                interface: "vf7".to_owned(),
                ifindex: 47,
                counter_bits: bits,
                values: (0..25)
                    .map(|index| {
                        if bits == 64 {
                            u64::MAX - index
                        } else {
                            u64::from(u32::MAX) - index
                        }
                    })
                    .collect(),
                carrier_changes: Some(u32::MAX),
            }];
            let generic: Vec<_> = links[0]
                .counters()
                .map(|(name, value, width)| MetricSample {
                    key: MetricKey::new("rtnetlink_link_stats", "link", name)
                        .with_label("interface", "vf7")
                        .with_label("ifindex", "47")
                        .with_label("counter_bits", if width == 64 { "64" } else { "32" }),
                    value,
                })
                .collect();
            let actual = translate_link_counters(&links).unwrap();
            assert_eq!(actual, translate_metrics(RTNETLINK_LINK, generic).unwrap());
            ProviderSample::new(
                provider_id(RTNETLINK_LINK),
                Duration::from_secs(1),
                Duration::ZERO,
                ProviderHealth::Fresh,
                actual,
            )
            .unwrap();
        }
    }

    #[test]
    fn preserves_counter_width_without_copying_private_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("interface".to_owned(), "eth0".to_owned());
        labels.insert("ifindex".to_owned(), "2".to_owned());
        labels.insert("counter_bits".to_owned(), "32".to_owned());
        labels.insert("queue".to_owned(), "7".to_owned());
        let readings = translated(
            RTNETLINK_LINK,
            vec![MetricSample {
                key: MetricKey {
                    source: "rtnetlink_link_stats".to_owned(),
                    group: "link".to_owned(),
                    metric: "rx_packets".to_owned(),
                    labels,
                },
                value: 99,
            }],
        );

        assert_eq!(readings[0].labels().len(), 2);
        assert_eq!(
            readings[0].labels().get(MetricLabel::Interface),
            Some("eth0")
        );
        assert_eq!(readings[0].labels().get(MetricLabel::Ifindex), Some("2"));
        assert!(matches!(
            readings[0].outcome(),
            ReadingOutcome::Observed(MetricReading::Counter {
                value: 99,
                bits: Some(CounterBits::Bits32)
            })
        ));
    }

    #[test]
    fn softnet_only_admits_rows_with_stable_cpu_identity() {
        let readings = translated(
            PROC_SOFTNET,
            vec![
                MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet", "dropped"),
                    value: 30,
                },
                MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet_cpu", "dropped")
                        .with_label("cpu_row", "0"),
                    value: 10,
                },
                MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet_cpu", "dropped")
                        .with_label("cpu", "3"),
                    value: 20,
                },
            ],
        );

        assert_eq!(readings.len(), 1);
        assert_eq!(
            readings[0].metric().as_str(),
            "linux.softirq.softnet.dropped"
        );
        assert_eq!(readings[0].labels().get(MetricLabel::Cpu), Some("3"));
    }

    #[test]
    fn softnet_queue_lengths_translate_as_per_cpu_gauges() {
        let readings = translated(
            PROC_SOFTNET,
            [("backlog_len", 7), ("input_qlen", 5), ("process_qlen", 2)]
                .into_iter()
                .map(|(metric, value)| MetricSample {
                    key: MetricKey::new("proc_softnet", "softnet_cpu", metric)
                        .with_label("cpu", "3"),
                    value,
                })
                .collect(),
        );

        assert_eq!(readings.len(), 3);
        for (reading, (metric, value)) in readings.iter().zip([
            ("linux.softirq.softnet.backlog_len", 7),
            ("linux.softirq.softnet.input_qlen", 5),
            ("linux.softirq.softnet.process_qlen", 2),
        ]) {
            assert_eq!(reading.metric().as_str(), metric);
            assert_eq!(reading.labels().get(MetricLabel::Cpu), Some("3"));
            assert!(matches!(
                reading.outcome(),
                ReadingOutcome::Observed(MetricReading::Gauge(current)) if *current == value
            ));
        }
    }

    #[test]
    fn net_core_softirq_settings_translate_as_host_gauges() {
        let readings = translated(
            PROC_SYS_NET_CORE,
            [
                ("netdev_budget", 300),
                ("netdev_budget_usecs", 2_000),
                ("dev_weight", 64),
                ("netdev_max_backlog", 1_000),
            ]
            .into_iter()
            .map(|(metric, value)| MetricSample {
                key: MetricKey::new("proc_sys_net_core", "net_core", metric),
                value,
            })
            .collect(),
        );

        assert_eq!(readings.len(), 4);
        for (reading, (metric, value)) in readings.iter().zip([
            ("linux.softirq.config.netdev_budget", 300),
            ("linux.softirq.config.netdev_budget_usecs", 2_000),
            ("linux.softirq.config.dev_weight", 64),
            ("linux.softirq.config.netdev_max_backlog", 1_000),
        ]) {
            assert_eq!(reading.metric().as_str(), metric);
            assert!(reading.labels().is_empty());
            assert!(matches!(
                reading.outcome(),
                ReadingOutcome::Observed(MetricReading::Gauge(current)) if *current == value
            ));
        }
    }

    #[test]
    fn translates_irq_rows_with_stable_interface_and_cpu_identity() {
        let softirq = translated(
            PROC_SOFTIRQS,
            vec![MetricSample {
                key: MetricKey::new("proc_softirqs", "softirq_cpu", "NET_RX")
                    .with_label("cpu", "3"),
                value: 11,
            }],
        );
        assert_eq!(softirq[0].metric().as_str(), "linux.softirq.net_rx");
        assert_eq!(softirq[0].labels().get(MetricLabel::Cpu), Some("3"));

        let hardirq = translated(
            PROC_INTERRUPTS,
            vec![MetricSample {
                key: MetricKey::new("proc_interrupts", "hardirq_cpu", "network_interrupts")
                    .with_label("interface", "eth0")
                    .with_label("ifindex", "2")
                    .with_label("cpu", "3")
                    .with_label("interrupt_class", "network"),
                value: 17,
            }],
        );
        assert_eq!(
            hardirq[0].metric().as_str(),
            "linux.hardirq.network_interrupts"
        );
        assert_eq!(
            hardirq[0].labels().get(MetricLabel::Interface),
            Some("eth0")
        );
        assert_eq!(hardirq[0].labels().get(MetricLabel::Ifindex), Some("2"));
        assert_eq!(hardirq[0].labels().get(MetricLabel::Cpu), Some("3"));
        assert_eq!(
            hardirq[0].labels().get(MetricLabel::InterruptClass),
            Some("network")
        );
    }

    #[test]
    fn incomplete_irq_affinity_is_unavailable_instead_of_partial() {
        let complete = translate_affinity(irq::AffinityRecord {
            interface: "eth0".to_owned(),
            ifindex: 2,
            cpu_list: Some("0-3".to_owned()),
            complete: true,
        })
        .unwrap();
        assert!(matches!(
            complete.outcome(),
            ReadingOutcome::Observed(MetricReading::State(value)) if value.as_str() == "0-3"
        ));

        let incomplete = translate_affinity(irq::AffinityRecord {
            interface: "eth0".to_owned(),
            ifindex: 2,
            cpu_list: Some("0-1".to_owned()),
            complete: false,
        })
        .unwrap();
        assert!(matches!(
            incomplete.outcome(),
            ReadingOutcome::Unavailable(UnavailableReason::Missing)
        ));
    }

    #[test]
    fn shared_hardirq_mapping_degrades_provider_without_exposing_irq_identity() {
        let root = tempdir().unwrap();
        let proc_root = root.path().join("proc");
        let sys_root = root.path().join("sys");
        fs::create_dir_all(sys_root.join("class/net/eth0/device/msi_irqs")).unwrap();
        fs::create_dir_all(sys_root.join("class/net/eth1/device")).unwrap();
        fs::create_dir_all(&proc_root).unwrap();
        fs::write(sys_root.join("class/net/eth0/ifindex"), "2\n").unwrap();
        fs::write(sys_root.join("class/net/eth1/ifindex"), "3\n").unwrap();
        fs::write(sys_root.join("class/net/eth0/device/msi_irqs/40"), "").unwrap();
        fs::write(sys_root.join("class/net/eth1/device/irq"), "40\n").unwrap();
        fs::write(proc_root.join("interrupts"), "CPU0\n40: 9 shared\n").unwrap();
        let paths = SystemPaths {
            proc_root,
            sys_root,
        };

        let sample = collect_hardirq_sample(Instant::now() - Duration::from_secs(1), &paths);

        assert!(matches!(
            sample.health(),
            ProviderHealth::Partial { warning }
                if warning.code() == MonitorErrorCode::Unsupported
                    && warning.diagnostic().contains("mapped to multiple network interfaces")
                    && !warning.diagnostic().contains("40")
        ));
        assert!(sample.readings().is_empty());
    }

    #[test]
    fn sysfs_nic_provider_emits_kind_from_the_collected_hardware_marker() {
        let collection = nic::NicCollection {
            interfaces: vec![
                nic::NicInterface {
                    interface: "veth0".to_owned(),
                    ifindex: 2,
                    hardware_backed: true,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::Failed(nic::EthtoolFailure::TimedOut),
                    ethtool: nic::EthtoolOutcome::Failed(nic::EthtoolFailure::TimedOut),
                },
                nic::NicInterface {
                    interface: "eth0".to_owned(),
                    ifindex: 3,
                    hardware_backed: false,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::NotHardwareInterface,
                    ethtool: nic::EthtoolOutcome::NotHardwareInterface,
                },
            ],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let sysfs = samples
            .iter()
            .find(|sample| sample.provider().as_str() == SYSFS_NIC)
            .unwrap();
        let kinds = sysfs
            .readings()
            .iter()
            .filter(|reading| reading.metric().as_str() == "linux.nic.interface_kind")
            .map(|reading| {
                let ReadingOutcome::Observed(MetricReading::State(value)) = reading.outcome()
                else {
                    panic!("interface kind must be an observed state")
                };
                (
                    reading
                        .labels()
                        .get(MetricLabel::Interface)
                        .expect("interface identity is required"),
                    value.as_str(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(kinds, vec![("eth0", "virtual"), ("veth0", "physical")]);
    }

    #[test]
    fn sysfs_nic_provider_maps_settings_as_observed_or_missing_states() {
        let collection = nic::NicCollection {
            interfaces: vec![nic::NicInterface {
                interface: "eth0".to_owned(),
                ifindex: 2,
                hardware_backed: true,
                operstate: nic::OperState::Up,
                sysfs: nic::NicSysfsInfo {
                    driver: Some("ixgbe".to_owned()),
                    rx_queue_count: Some(8),
                    tx_queue_count: None,
                    tx_queue_len: Some(1_000),
                    mtu: Some(9_000),
                },
                channels: Vec::new(),
                fallback_settings: Vec::new(),
                settings: nic::EthtoolSettingsOutcome::NotHardwareInterface,
                ethtool: nic::EthtoolOutcome::NotHardwareInterface,
            }],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let sysfs = samples
            .iter()
            .find(|sample| sample.provider().as_str() == SYSFS_NIC)
            .unwrap();
        let setting = |statistic: &str| {
            sysfs
                .readings()
                .iter()
                .find(|reading| {
                    reading.metric().as_str() == super::super::RAW_NIC_SETTING_METRIC_ID
                        && reading.labels().get(MetricLabel::Statistic) == Some(statistic)
                })
                .unwrap()
        };

        assert_eq!(
            sysfs
                .readings()
                .iter()
                .filter(|reading| {
                    reading.metric().as_str() == super::super::RAW_NIC_SETTING_METRIC_ID
                })
                .count(),
            4
        );
        assert!(sysfs.readings().iter().all(|reading| {
            reading.labels().get(MetricLabel::Interface) == Some("eth0")
                && reading.labels().get(MetricLabel::Ifindex) == Some("2")
        }));
        assert!(matches!(
            setting("Driver").outcome(),
            ReadingOutcome::Observed(MetricReading::State(value)) if value.as_str() == "ixgbe"
        ));
        assert!(matches!(
            setting("RX Queues").outcome(),
            ReadingOutcome::Observed(MetricReading::State(value)) if value.as_str() == "8"
        ));
        assert!(matches!(
            setting("TX Queues").outcome(),
            ReadingOutcome::Unavailable(UnavailableReason::Missing)
        ));
        assert!(matches!(
            setting("TX Queue Length").outcome(),
            ReadingOutcome::Observed(MetricReading::State(value)) if value.as_str() == "1000"
        ));
        assert!(sysfs.readings().iter().any(|reading| {
            reading.metric().as_str() == "linux.nic.mtu"
                && reading.outcome() == &ReadingOutcome::Observed(MetricReading::Gauge(9_000))
        }));
    }

    #[test]
    fn nic_mtu_refreshes_as_a_gauge_on_virtual_interfaces_without_settings_queries() {
        let mut interface = nic_interface("veth0", 2, "512");
        interface.hardware_backed = false;
        interface.settings = nic::EthtoolSettingsOutcome::NotHardwareInterface;
        interface.ethtool = nic::EthtoolOutcome::NotHardwareInterface;
        let mut collection = nic::NicCollection {
            interfaces: vec![interface],
            errors: Vec::new(),
        };
        let mut cache = NicReadingsCache::default();
        for mtu in [Some(1500), Some(9000), None] {
            collection.interfaces[0].sysfs.mtu = mtu;
            let samples = nic_dynamic_samples(&mut cache, &collection, 1);
            let sysfs = samples
                .iter()
                .find(|sample| sample.provider().as_str() == SYSFS_NIC)
                .unwrap();
            let reading = sysfs
                .readings()
                .iter()
                .find(|reading| reading.metric().as_str() == "linux.nic.mtu")
                .unwrap();
            let expected = match mtu {
                Some(mtu) => ReadingOutcome::Observed(MetricReading::Gauge(u64::from(mtu))),
                None => ReadingOutcome::Unavailable(UnavailableReason::Missing),
            };
            assert_eq!(reading.outcome(), &expected);
            assert_eq!(reading.labels().get(MetricLabel::Interface), Some("veth0"));
            assert_eq!(reading.labels().get(MetricLabel::Ifindex), Some("2"));
        }
    }

    #[test]
    fn sysfs_nic_budget_preserves_interface_inventory_before_link_state_and_settings() {
        let interfaces = (0_u32..2_049)
            .map(|index| nic::NicInterface {
                interface: format!("v{index}"),
                ifindex: index + 1,
                hardware_backed: false,
                operstate: nic::OperState::Up,
                sysfs: nic::NicSysfsInfo::default(),
                channels: Vec::new(),
                fallback_settings: Vec::new(),
                settings: nic::EthtoolSettingsOutcome::NotHardwareInterface,
                ethtool: nic::EthtoolOutcome::NotHardwareInterface,
            })
            .collect();
        let samples = translate_nic_collection(
            nic::NicCollection {
                interfaces,
                errors: vec![nic::NicCollectionError {
                    interface: Some("broken0".to_owned()),
                    kind: nic::NicCollectionErrorKind::ReadIfindex,
                    detail: "broken0: cannot read ifindex".to_owned(),
                }],
            },
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let sysfs = samples
            .iter()
            .find(|sample| sample.provider().as_str() == SYSFS_NIC)
            .unwrap();

        assert!(matches!(
            sysfs.health(),
            ProviderHealth::Partial { warning }
                if warning.code() == MonitorErrorCode::CardinalityLimit
                    && warning.diagnostic().contains("omitted 0 interface kind readings")
                    && warning
                        .diagnostic()
                        .contains("10247 link-state or setting readings")
                    && warning.diagnostic().contains("cannot read ifindex")
        ));
        assert_eq!(sysfs.readings().len(), MAX_READINGS_PER_PROVIDER);
        assert_eq!(
            sysfs
                .readings()
                .iter()
                .filter(|reading| reading.metric().as_str() == "linux.nic.interface_kind")
                .count(),
            2_049
        );
        assert_eq!(
            sysfs
                .readings()
                .iter()
                .filter(|reading| reading.metric().as_str() == "linux.nic.link_state")
                .count(),
            2_047
        );
        assert_eq!(
            sysfs
                .readings()
                .iter()
                .filter(|reading| {
                    reading.metric().as_str() == super::super::RAW_NIC_SETTING_METRIC_ID
                })
                .count(),
            0
        );
    }

    #[test]
    fn mixed_ethtool_results_keep_successful_interfaces_and_report_partial_health() {
        let collection = nic::NicCollection {
            interfaces: vec![
                nic::NicInterface {
                    interface: "eth0".to_owned(),
                    ifindex: 2,
                    hardware_backed: true,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::Collected(
                        nic::EthtoolSettings::default(),
                    ),
                    ethtool: nic::EthtoolOutcome::Collected(nic::NicStatistics {
                        standard: Vec::new(),
                        private: vec![nic::PrivateNicStatistic {
                            name: "driver_stat".to_owned(),
                            value: 7,
                            semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
                        }],
                    }),
                },
                nic::NicInterface {
                    interface: "eth1".to_owned(),
                    ifindex: 3,
                    hardware_backed: true,
                    operstate: nic::OperState::Down,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::Collected(
                        nic::EthtoolSettings::default(),
                    ),
                    ethtool: nic::EthtoolOutcome::Failed(nic::EthtoolFailure::TimedOut),
                },
            ],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let ethtool = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_TEXT)
            .unwrap();

        assert!(matches!(
            ethtool.health(),
            ProviderHealth::Partial { warning }
                if warning.code() == MonitorErrorCode::Timeout
                    && warning.diagnostic().contains("eth1")
        ));
        assert_eq!(ethtool.readings().len(), 3);
        assert_eq!(
            ethtool
                .readings()
                .iter()
                .filter(|reading| {
                    reading.metric().as_str() == "linux.nic.ethtool_statistics_status"
                })
                .map(|reading| {
                    let ReadingOutcome::Observed(MetricReading::State(value)) = reading.outcome()
                    else {
                        panic!("ethtool status must be an observed state")
                    };
                    (
                        reading.labels().get(MetricLabel::Interface).unwrap(),
                        value.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [("eth0", "complete"), ("eth1", "timed_out")]
        );
    }

    #[test]
    fn all_ethtool_setting_failures_still_emit_per_interface_statuses() {
        let interface = |name: &str, ifindex: u32, failure| nic::NicInterface {
            interface: name.to_owned(),
            ifindex,
            hardware_backed: true,
            operstate: nic::OperState::Up,
            sysfs: nic::NicSysfsInfo::default(),
            channels: Vec::new(),
            fallback_settings: Vec::new(),
            settings: nic::EthtoolSettingsOutcome::Failed(failure),
            ethtool: nic::EthtoolOutcome::Collected(nic::NicStatistics::default()),
        };
        let collection = nic::NicCollection {
            interfaces: vec![
                interface("eth0", 2, nic::EthtoolFailure::TimedOut),
                interface("eth1", 3, nic::EthtoolFailure::CommandNotFound),
                interface(
                    "eth2",
                    4,
                    nic::EthtoolFailure::PermissionDenied {
                        detail: "Operation not permitted".to_owned(),
                    },
                ),
            ],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let settings = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap();

        assert!(matches!(
            settings.health(),
            ProviderHealth::Partial { warning }
                if warning.code() == MonitorErrorCode::Timeout
        ));
        assert_eq!(
            settings
                .readings()
                .iter()
                .map(|reading| {
                    let ReadingOutcome::Observed(MetricReading::State(value)) = reading.outcome()
                    else {
                        panic!("settings outcome must be an observed state")
                    };
                    (
                        reading.labels().get(MetricLabel::Interface).unwrap(),
                        value.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [
                ("eth0", "timed_out"),
                ("eth1", "command_not_found"),
                ("eth2", "permission_denied"),
            ]
        );
    }

    #[test]
    fn packed_interface_readings_preserve_round_robin_selection_and_omissions() {
        fn check_case(lengths: &[usize], limits: impl IntoIterator<Item = usize>) {
            let groups = lengths
                .iter()
                .enumerate()
                .map(|(group, &length)| {
                    let interface = nic_interface(&format!("e{group}"), group as u32 + 1, "512");
                    (0..length)
                        .map(|row| {
                            if row == 0 {
                                ethtool_status_reading(
                                    super::super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
                                    interface_labels(&interface.interface, interface.ifindex)
                                        .unwrap(),
                                    "complete",
                                )
                            } else {
                                SampleReading::observed(
                                    MetricId::new(super::super::RAW_NIC_SETTING_METRIC_ID).unwrap(),
                                    nic_statistic_labels(&interface, &format!("field_{row}"))
                                        .unwrap(),
                                    MetricReading::State(
                                        StateValue::new(format!("value_{group}_{row}")).unwrap(),
                                    ),
                                )
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            // The old traversal emits row n of every group before row n + 1.
            let round_robin = (0..lengths.iter().copied().max().unwrap_or(0))
                .flat_map(|row| {
                    lengths
                        .iter()
                        .enumerate()
                        .filter_map(move |(group, &length)| (row < length).then_some((group, row)))
                })
                .collect::<Vec<_>>();
            let canonical = |readings| {
                ProviderSample::new(
                    provider_id(ETHTOOL_LINK_TEXT),
                    Duration::from_secs(1),
                    Duration::ZERO,
                    ProviderHealth::Fresh,
                    readings,
                )
                .unwrap()
            };
            for limit in limits {
                let expected = round_robin
                    .iter()
                    .take(limit)
                    .map(|&(group, row)| groups[group][row].clone())
                    .collect();
                let mut omitted_primary = 0;
                let mut omitted_payload_by_group = vec![0; groups.len()];
                for &(group, row) in round_robin.iter().skip(limit) {
                    if row == 0 {
                        omitted_primary += 1;
                    } else {
                        omitted_payload_by_group[group] += 1;
                    }
                }
                let actual = interleave_readings(groups.clone(), limit);
                assert_eq!(
                    canonical(actual.readings),
                    canonical(expected),
                    "lengths={lengths:?}, limit={limit}"
                );
                assert_eq!(
                    (
                        actual.omitted_primary,
                        actual.omitted_payload,
                        actual.omitted_payload_by_group,
                    ),
                    (
                        omitted_primary,
                        omitted_payload_by_group.iter().sum::<usize>(),
                        omitted_payload_by_group,
                    ),
                    "lengths={lengths:?}, limit={limit}"
                );
            }
        }

        for group_count in 0..=4 {
            for mut encoded in 0..5_usize.pow(group_count) {
                let lengths = (0..group_count)
                    .map(|_| {
                        let length = encoded % 5;
                        encoded /= 5;
                        length
                    })
                    .collect::<Vec<_>>();
                check_case(&lengths, 0..=lengths.iter().sum::<usize>() + 1);
            }
        }
        for lengths in [
            vec![0, MAX_READINGS_PER_PROVIDER + 2, 1, 3, 7],
            vec![7, 3, 1, MAX_READINGS_PER_PROVIDER + 2, 0],
            vec![2; MAX_READINGS_PER_PROVIDER + 1],
        ] {
            check_case(
                &lengths,
                [
                    0,
                    1,
                    4,
                    5,
                    6,
                    MAX_READINGS_PER_PROVIDER - 1,
                    MAX_READINGS_PER_PROVIDER,
                ],
            );
        }
        check_case(&[0, 3, 1, 0, 4], [usize::MAX]);
    }

    #[test]
    fn interface_statuses_are_prioritized_and_counted_separately_from_payload() {
        let groups = (0..=MAX_READINGS_PER_PROVIDER)
            .map(|index| {
                vec![ethtool_status_reading(
                    super::super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
                    interface_labels(&format!("e{index}"), (index + 1) as u32).unwrap(),
                    "complete",
                )]
            })
            .collect::<Vec<_>>();

        let bounded = interleave_readings(groups, MAX_READINGS_PER_PROVIDER);

        assert_eq!(bounded.readings.len(), MAX_READINGS_PER_PROVIDER);
        assert_eq!(bounded.omitted_primary, 1);
        assert_eq!(bounded.omitted_payload, 0);
        assert!(bounded
            .omitted_payload_by_group
            .iter()
            .all(|omitted| *omitted == 0));
        assert_eq!(
            bounded.readings[0].labels().get(MetricLabel::Interface),
            Some("e0")
        );
        assert_eq!(
            bounded.readings[MAX_READINGS_PER_PROVIDER - 1]
                .labels()
                .get(MetricLabel::Interface),
            Some("e4095")
        );
    }

    #[test]
    fn ethtool_link_settings_are_an_independent_opaque_provider() {
        let collection = nic::NicCollection {
            interfaces: vec![nic::NicInterface {
                interface: "eth0".to_owned(),
                ifindex: 2,
                hardware_backed: true,
                operstate: nic::OperState::Up,
                sysfs: nic::NicSysfsInfo::default(),
                channels: Vec::new(),
                fallback_settings: Vec::new(),
                settings: nic::EthtoolSettingsOutcome::Collected(nic::EthtoolSettings {
                    fields: vec![
                        nic::EthtoolSetting {
                            name: "Speed".to_owned(),
                            value: "10000Mb/s".to_owned(),
                        },
                        nic::EthtoolSetting {
                            name: "Link detected".to_owned(),
                            value: "yes".to_owned(),
                        },
                    ],
                }),
                ethtool: nic::EthtoolOutcome::Failed(nic::EthtoolFailure::TimedOut),
            }],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let settings = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap();
        let statistics = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_TEXT)
            .unwrap();

        assert!(matches!(settings.health(), ProviderHealth::Fresh));
        assert_eq!(settings.readings().len(), 3);
        assert!(settings
            .readings()
            .iter()
            .filter(|reading| {
                reading.metric().as_str() == super::super::RAW_NIC_SETTING_METRIC_ID
            })
            .all(|reading| {
                reading.metric().as_str() == super::super::RAW_NIC_SETTING_METRIC_ID
                    && reading.labels().get(MetricLabel::Interface) == Some("eth0")
                    && matches!(
                        reading.outcome(),
                        crate::monitor::ReadingOutcome::Observed(MetricReading::State(_))
                    )
            }));
        assert!(matches!(
            statistics.health(),
            ProviderHealth::Partial { warning }
                if warning.code() == MonitorErrorCode::Timeout
        ));
        assert!(statistics.readings().iter().any(|reading| {
            reading.metric().as_str() == "linux.nic.ethtool_statistics_status"
                && matches!(
                    reading.outcome(),
                    ReadingOutcome::Observed(MetricReading::State(value))
                        if value.as_str() == "timed_out"
                )
        }));
    }

    #[test]
    fn ethtool_setting_schema_partial_remains_visible_when_provider_budget_is_exceeded() {
        let fields = (0..MAX_READINGS_PER_PROVIDER)
            .map(|index| nic::EthtoolSetting {
                name: format!("setting_{index:04}"),
                value: "enabled".to_owned(),
            })
            .collect();
        let collection = nic::NicCollection {
            interfaces: vec![nic::NicInterface {
                interface: "eth0".to_owned(),
                ifindex: 2,
                hardware_backed: true,
                operstate: nic::OperState::Up,
                sysfs: nic::NicSysfsInfo::default(),
                channels: Vec::new(),
                fallback_settings: Vec::new(),
                settings: nic::EthtoolSettingsOutcome::Partial {
                    settings: nic::EthtoolSettings { fields },
                    rejected_lines: 3,
                },
                ethtool: nic::EthtoolOutcome::Collected(nic::NicStatistics::default()),
            }],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let settings = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap();
        let ProviderHealth::Partial { warning } = settings.health() else {
            panic!("settings provider must report partial health");
        };

        assert_eq!(settings.readings().len(), MAX_READINGS_PER_PROVIDER);
        assert_eq!(warning.code(), MonitorErrorCode::CardinalityLimit);
        assert!(warning.diagnostic().contains("rejected=3"));
        assert!(warning.diagnostic().contains("omitted 1 setting fields"));
        assert!(!warning.diagnostic().contains("2/1"));
        assert!(settings.readings().iter().any(|reading| {
            reading.metric().as_str() == super::super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID
                && reading.labels().get(MetricLabel::Interface) == Some("eth0")
                && matches!(
                    reading.outcome(),
                    ReadingOutcome::Observed(MetricReading::State(value))
                        if value.as_str() == "partial_cardinality_limit"
                )
        }));
    }

    #[test]
    fn ethtool_statistic_schema_partial_remains_visible_when_provider_budget_is_exceeded() {
        let private = (0..MAX_READINGS_PER_PROVIDER)
            .map(|index| nic::PrivateNicStatistic {
                name: format!("driver_{index:04}"),
                value: index as u64,
                semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
            })
            .collect();
        let collection = nic::NicCollection {
            interfaces: vec![nic::NicInterface {
                interface: "eth0".to_owned(),
                ifindex: 2,
                hardware_backed: true,
                operstate: nic::OperState::Up,
                sysfs: nic::NicSysfsInfo::default(),
                channels: Vec::new(),
                fallback_settings: Vec::new(),
                settings: nic::EthtoolSettingsOutcome::Collected(nic::EthtoolSettings::default()),
                ethtool: nic::EthtoolOutcome::Partial {
                    statistics: nic::NicStatistics {
                        standard: Vec::new(),
                        private,
                    },
                    rejected_lines: 4,
                    omitted_private: 2,
                },
            }],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let statistics = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_TEXT)
            .unwrap();
        let ProviderHealth::Partial { warning } = statistics.health() else {
            panic!("statistics provider must report partial health");
        };

        assert_eq!(statistics.readings().len(), MAX_READINGS_PER_PROVIDER);
        assert_eq!(warning.code(), MonitorErrorCode::CardinalityLimit);
        assert!(warning.diagnostic().contains("rejected=4"));
        assert!(warning.diagnostic().contains("private_omitted=2"));
        assert!(warning.diagnostic().contains("omitted 1 statistics"));
        assert!(!warning.diagnostic().contains("2/1"));
        assert!(statistics.readings().iter().any(|reading| {
            reading.metric().as_str() == super::super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID
                && reading.labels().get(MetricLabel::Interface) == Some("eth0")
                && matches!(
                    reading.outcome(),
                    ReadingOutcome::Observed(MetricReading::State(value))
                        if value.as_str() == "partial_cardinality_limit"
                )
        }));
    }

    #[test]
    fn ethtool_setting_cardinality_preserves_issue_counts_with_long_failure() {
        let fields = (0..MAX_READINGS_PER_PROVIDER)
            .map(|index| nic::EthtoolSetting {
                name: format!("setting_{index:04}"),
                value: "enabled".to_owned(),
            })
            .collect();
        let collection = nic::NicCollection {
            interfaces: vec![
                nic::NicInterface {
                    interface: "failed0".to_owned(),
                    ifindex: 2,
                    hardware_backed: true,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::Failed(
                        nic::EthtoolFailure::ExitFailure {
                            code: Some(1),
                            detail: format!("LONG_STDERR_{}", "x".repeat(512)),
                        },
                    ),
                    ethtool: nic::EthtoolOutcome::Collected(nic::NicStatistics::default()),
                },
                nic::NicInterface {
                    interface: "partial0".to_owned(),
                    ifindex: 3,
                    hardware_backed: true,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::Partial {
                        settings: nic::EthtoolSettings { fields },
                        rejected_lines: 3,
                    },
                    ethtool: nic::EthtoolOutcome::Collected(nic::NicStatistics::default()),
                },
            ],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let settings = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_LINK_TEXT)
            .unwrap();
        let ProviderHealth::Partial { warning } = settings.health() else {
            panic!("settings provider must report partial health");
        };
        let diagnostic = warning.diagnostic();

        assert_eq!(warning.code(), MonitorErrorCode::CardinalityLimit);
        assert!(diagnostic.contains("omitted 2 setting fields"));
        assert!(diagnostic.contains("failures 1"));
        assert!(diagnostic.contains("schema partials 1"));
        assert!(diagnostic.contains("first failure failed0: command_failed"));
        assert!(diagnostic.contains("first schema partial partial0: rejected=3"));
        assert!(!diagnostic.contains("LONG_STDERR"));
        assert!(diagnostic.len() <= super::super::model::MAX_DIAGNOSTIC_BYTES);
    }

    #[test]
    fn ethtool_statistic_cardinality_preserves_issue_counts_with_long_failure() {
        let private = (0..MAX_READINGS_PER_PROVIDER)
            .map(|index| nic::PrivateNicStatistic {
                name: format!("driver_{index:04}"),
                value: index as u64,
                semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
            })
            .collect();
        let collection = nic::NicCollection {
            interfaces: vec![
                nic::NicInterface {
                    interface: "failed0".to_owned(),
                    ifindex: 2,
                    hardware_backed: true,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::Collected(
                        nic::EthtoolSettings::default(),
                    ),
                    ethtool: nic::EthtoolOutcome::Failed(nic::EthtoolFailure::ExitFailure {
                        code: Some(1),
                        detail: format!("LONG_STDERR_{}", "x".repeat(512)),
                    }),
                },
                nic::NicInterface {
                    interface: "partial0".to_owned(),
                    ifindex: 3,
                    hardware_backed: true,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::Collected(
                        nic::EthtoolSettings::default(),
                    ),
                    ethtool: nic::EthtoolOutcome::Partial {
                        statistics: nic::NicStatistics {
                            standard: Vec::new(),
                            private,
                        },
                        rejected_lines: 4,
                        omitted_private: 2,
                    },
                },
            ],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let statistics = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_TEXT)
            .unwrap();
        let ProviderHealth::Partial { warning } = statistics.health() else {
            panic!("statistics provider must report partial health");
        };
        let diagnostic = warning.diagnostic();

        assert_eq!(warning.code(), MonitorErrorCode::CardinalityLimit);
        assert!(diagnostic.contains("omitted 2 statistics"));
        assert!(diagnostic.contains("failures 1"));
        assert!(diagnostic.contains("schema partials 1"));
        assert!(diagnostic.contains("first failure failed0: command_failed"));
        assert!(diagnostic.contains("first schema partial partial0: rejected=4, private_omitted=2"));
        assert!(!diagnostic.contains("LONG_STDERR"));
        assert!(diagnostic.len() <= super::super::model::MAX_DIAGNOSTIC_BYTES);
    }

    #[test]
    fn ethtool_statistic_budget_is_fair_and_explicitly_partial() {
        let private = |prefix: &str| {
            (0..2_050)
                .map(|index| nic::PrivateNicStatistic {
                    name: format!("{prefix}_{index:04}"),
                    value: index,
                    semantics: nic::NicStatisticSemantics::OpaqueCurrentOnly,
                })
                .collect()
        };
        let interface = |name: &str, ifindex: u32, prefix: &str| nic::NicInterface {
            interface: name.to_owned(),
            ifindex,
            hardware_backed: true,
            operstate: nic::OperState::Up,
            sysfs: nic::NicSysfsInfo::default(),
            channels: Vec::new(),
            fallback_settings: Vec::new(),
            settings: nic::EthtoolSettingsOutcome::Collected(nic::EthtoolSettings::default()),
            ethtool: nic::EthtoolOutcome::Collected(nic::NicStatistics {
                standard: Vec::new(),
                private: private(prefix),
            }),
        };
        let collection = nic::NicCollection {
            interfaces: vec![interface("eth0", 2, "a"), interface("eth1", 3, "b")],
            errors: Vec::new(),
        };

        let samples = translate_nic_collection(
            collection,
            Duration::from_secs(2),
            Duration::from_millis(30),
        );
        let statistics = samples
            .iter()
            .find(|sample| sample.provider().as_str() == ETHTOOL_TEXT)
            .unwrap();

        assert_eq!(statistics.readings().len(), MAX_READINGS_PER_PROVIDER);
        assert!(matches!(
            statistics.health(),
                ProviderHealth::Partial { warning }
                    if warning.code() == MonitorErrorCode::CardinalityLimit
                    && warning.diagnostic().contains("omitted 6 statistics")
        ));
        for interface in ["eth0", "eth1"] {
            assert_eq!(
                statistics
                    .readings()
                    .iter()
                    .filter(|reading| {
                        reading.labels().get(MetricLabel::Interface) == Some(interface)
                    })
                    .count(),
                MAX_READINGS_PER_PROVIDER / 2
            );
        }
        assert_eq!(
            statistics
                .readings()
                .iter()
                .filter(|reading| {
                    reading.metric().as_str()
                        == super::super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID
                })
                .map(|reading| {
                    let ReadingOutcome::Observed(MetricReading::State(value)) = reading.outcome()
                    else {
                        panic!("statistics outcome must be an observed state")
                    };
                    (
                        reading.labels().get(MetricLabel::Interface).unwrap(),
                        value.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [
                ("eth0", "partial_cardinality_limit"),
                ("eth1", "partial_cardinality_limit")
            ]
        );
    }

    #[test]
    fn qdisc_rows_use_stable_opaque_ids_and_explicit_missing_values() {
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        let input = br#"[
            {"kind":"fq_codel","handle":"1:","dev":"eth0","root":true,
             "packets":10,"bytes":1000,"drops":2,"overlimits":3,"requeues":4,
             "backlog":50,"qlen":5,"maxpacket":1514,"drop_overlimit":6,
             "new_flow_count":7,"ecn_mark":8,"new_flows_len":9,"old_flows_len":10},
            {"kind":"ingress","handle":"ffff:","parent":"ffff:fff1","dev":"eth0",
             "packets":7},
            {"kind":"clsact","handle":"ffff:","dev":"eth0","root":true,
             "packets":99}
        ]"#;
        let rows = tc::parse_qdiscs_for_test(input, root.path()).unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().to_owned(),
        });

        let first = collector
            .translate_qdisc_rows(rows)
            .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(first.len(), 20);
        provider_sample(
            TC_JSON,
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            first.clone(),
        );
        assert!(first.iter().all(|reading| {
            reading.labels().get(MetricLabel::Interface) == Some("eth0")
                && reading.labels().get(MetricLabel::Ifindex) == Some("2")
                && reading.labels().get(MetricLabel::ObjectKind) == Some("qdisc")
                && reading.labels().get(MetricLabel::QdiscKind).is_some()
                && reading.labels().get(MetricLabel::Execution) == Some("software")
                && reading.labels().get(MetricLabel::Handle).is_none()
                && reading.labels().get(MetricLabel::QdiscAttachment).is_some()
        }));
        let ingress_drop = first
            .iter()
            .find(|reading| {
                reading.metric().as_str() == "linux.tc.drops"
                    && reading.labels().get(MetricLabel::Direction) == Some("ingress")
            })
            .unwrap();
        assert_eq!(
            ingress_drop.labels().get(MetricLabel::QdiscAttachment),
            Some(r#"[false,"ffff:","ffff:fff1"]"#)
        );
        assert!(matches!(
            ingress_drop.outcome(),
            ReadingOutcome::Unavailable(UnavailableReason::Missing)
        ));
        for metric in [
            "linux.tc.max_packet_bytes",
            "linux.tc.drop_overlimit",
            "linux.tc.new_flow_count",
            "linux.tc.ecn_marks",
            "linux.tc.new_flows_len",
            "linux.tc.old_flows_len",
        ] {
            assert!(!first.iter().any(|reading| {
                reading.metric().as_str() == metric
                    && reading.labels().get(MetricLabel::Direction) == Some("ingress")
            }));
        }
        let egress_reading = |metric: &str| {
            first
                .iter()
                .find(|reading| {
                    reading.metric().as_str() == metric
                        && reading.labels().get(MetricLabel::Direction) == Some("egress")
                })
                .unwrap()
        };
        assert!(matches!(
            egress_reading("linux.tc.max_packet_bytes").outcome(),
            ReadingOutcome::Observed(MetricReading::Gauge(1514))
        ));
        for (metric, value) in [
            ("linux.tc.drop_overlimit", 6),
            ("linux.tc.new_flow_count", 7),
            ("linux.tc.ecn_marks", 8),
        ] {
            assert!(matches!(
                egress_reading(metric).outcome(),
                ReadingOutcome::Observed(MetricReading::Counter {
                    value: observed,
                    bits: Some(CounterBits::Bits32)
                }) if *observed == value
            ));
        }
        for (metric, value) in [
            ("linux.tc.new_flows_len", 9),
            ("linux.tc.old_flows_len", 10),
        ] {
            assert!(matches!(
                egress_reading(metric).outcome(),
                ReadingOutcome::Observed(MetricReading::Gauge(observed)) if *observed == value
            ));
        }

        let first_ids = first
            .iter()
            .map(|reading| reading.labels().get(MetricLabel::RowId).unwrap())
            .collect::<BTreeSet<_>>();
        let second_rows = tc::parse_qdiscs_for_test(input, root.path()).unwrap();
        let second = collector
            .translate_qdisc_rows(second_rows)
            .unwrap_or_else(|error| panic!("{}", error.message));
        let second_ids = second
            .iter()
            .map(|reading| reading.labels().get(MetricLabel::RowId).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(first_ids, second_ids);
    }

    #[test]
    fn qdisc_attachments_and_row_ids_survive_reordering_and_distinguish_shared_handles() {
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        let input = br#"[
            {"kind":"mq","handle":"0:","dev":"eth0","root":true},
            {"kind":"fq_codel","handle":"0:","dev":"eth0","parent":":1"},
            {"kind":"fq_codel","handle":"0:","dev":"eth0","parent":":2"}
        ]"#;
        let rows = tc::parse_qdiscs_for_test(input, root.path()).unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().to_owned(),
        });
        let ids = |readings: Vec<SampleReading>| {
            readings
                .into_iter()
                .map(|reading| {
                    (
                        reading
                            .labels()
                            .get(MetricLabel::QdiscAttachment)
                            .unwrap()
                            .to_owned(),
                        reading.labels().get(MetricLabel::RowId).unwrap().to_owned(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let first = ids(collector
            .translate_qdisc_rows(rows.clone())
            .unwrap_or_else(|error| panic!("{}", error.message)));
        let second = ids(collector
            .translate_qdisc_rows(rows.into_iter().rev().collect())
            .unwrap_or_else(|error| panic!("{}", error.message)));
        assert_eq!(first, second);
        assert_eq!(first.len(), 3);
        assert_eq!(first.values().collect::<BTreeSet<_>>().len(), 3);
    }

    #[test]
    fn native_tc_uses_json_only_on_failure_and_preserves_missing_values() {
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        let rows = tc::parse_qdiscs_for_test(
            br#"[{"kind":"fq_codel","handle":"1:","dev":"eth0","root":true}]"#,
            root.path(),
        )
        .unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().to_owned(),
        });
        let start = Instant::now() - Duration::from_secs(1);
        let native =
            collector.finish_tc_collection(start, Instant::now(), Ok(rows.clone()), || {
                panic!("native success must not spawn tc")
            });
        assert_eq!(native[0].provider().as_str(), TC_NETLINK);
        assert!(native[0].health().is_fresh());
        assert!(native[0].readings().iter().all(|reading| matches!(
            reading.outcome(),
            ReadingOutcome::Unavailable(UnavailableReason::Missing)
        )));
        assert!(matches!(
            native[1].health(),
            ProviderHealth::Unsupported { .. }
        ));
        let malformed = tc::parse_qdiscs_for_test(b"not json", root.path());
        let fallback =
            collector.finish_tc_collection(start, Instant::now(), malformed, || Ok(rows.clone()));
        assert!(!fallback[0].health().is_fresh());
        assert_eq!(fallback[1].provider().as_str(), TC_JSON);
        assert!(fallback[1].health().is_fresh());
        assert_eq!(native[0].readings(), fallback[1].readings());
        let failed = collector.finish_tc_collection(
            start,
            Instant::now(),
            tc::parse_qdiscs_for_test(b"bad", root.path()),
            || tc::parse_qdiscs_for_test(b"bad", root.path()),
        );
        assert!(failed
            .iter()
            .all(|sample| !sample.health().is_fresh() && sample.readings().is_empty()));
    }

    #[test]
    fn tc_backend_switch_keeps_identity_but_rewarms_rates() {
        use crate::monitor::session::MonitorEngine;
        use crate::monitor::{CounterContinuity, ProjectedValue, SeriesValue};
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().to_owned(),
        });
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let mut id = None;
        for (second, source) in [
            (1, TC_NETLINK),
            (2, TC_NETLINK),
            (3, TC_JSON),
            (4, TC_JSON),
            (5, TC_NETLINK),
        ] {
            let json = format!(
                r#"[{{"kind":"fq_codel","handle":"1:","dev":"eth0","root":true,"drops":{}}}]"#,
                second * 10
            );
            let rows = tc::parse_qdiscs_for_test(json.as_bytes(), root.path()).unwrap();
            let readings = collector
                .translate_qdisc_rows(rows)
                .unwrap_or_else(|error| panic!("{}", error.message));
            let at = Duration::from_secs(second);
            let snapshot = engine
                .ingest(
                    at,
                    vec![provider_sample(
                        source,
                        at,
                        Duration::ZERO,
                        ProviderHealth::Fresh,
                        readings,
                    )],
                    None,
                )
                .unwrap();
            let drop = snapshot
                .series()
                .iter()
                .find(|series| series.metric().as_str() == "linux.tc.drops")
                .unwrap();
            assert_eq!(*id.get_or_insert(drop.id()), drop.id());
            let SeriesValue::Counter {
                current, interval, ..
            } = drop.value()
            else {
                panic!("counter expected");
            };
            assert!(matches!(current, ProjectedValue::Fresh { .. }));
            if matches!(second, 2 | 4) {
                assert_eq!(
                    interval.and_then(CounterContinuity::rate_per_second),
                    Some(10.0)
                );
            } else {
                assert_eq!(interval.and_then(CounterContinuity::rate_per_second), None);
            }
        }
    }

    #[test]
    fn tc_native_queue_and_basic_packet_widths_produce_wrap_rates() {
        use crate::monitor::session::MonitorEngine;
        use crate::monitor::{CounterContinuity, SeriesValue};
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().to_owned(),
        });
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        for (second, value) in [(1, u32::MAX - 2), (2, 4)] {
            let input = format!(
                r#"[{{"kind":"fq_codel","handle":"1:","dev":"eth0","root":true,"drops":{value},"packets":{value},"requeues":{value},"overlimits":{value}}}]"#
            );
            let mut rows = tc::parse_qdiscs_for_test(input.as_bytes(), root.path()).unwrap();
            rows[0].counter_bits.packets = Some(32);
            rows[0].counter_bits.drops = Some(32);
            rows[0].counter_bits.requeues = Some(32);
            rows[0].counter_bits.overlimits = Some(32);
            let readings = collector
                .translate_qdisc_rows(rows)
                .unwrap_or_else(|error| panic!("{}", error.message));
            let at = Duration::from_secs(second);
            let sample = provider_sample(
                TC_NETLINK,
                at,
                Duration::ZERO,
                ProviderHealth::Fresh,
                readings,
            );
            let snapshot = engine.ingest(at, vec![sample], None).unwrap();
            if second == 2 {
                for metric in [
                    "linux.tc.packets",
                    "linux.tc.drops",
                    "linux.tc.requeues",
                    "linux.tc.overlimits",
                ] {
                    let series = snapshot
                        .series()
                        .iter()
                        .find(|series| series.metric().as_str() == metric)
                        .unwrap();
                    let SeriesValue::Counter {
                        interval: Some(interval),
                        ..
                    } = series.value()
                    else {
                        panic!("interval expected");
                    };
                    assert!(matches!(
                        interval,
                        CounterContinuity::Wrapped {
                            bits: CounterBits::Bits32,
                            ..
                        }
                    ));
                    assert_eq!(interval.rate_per_second(), Some(7.0));
                }
            }
        }
    }

    #[test]
    fn fq_codel_missing_extended_statistics_are_explicitly_unavailable() {
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        let rows = tc::parse_qdiscs_for_test(
            br#"[{"kind":"fq_codel","handle":"1:","dev":"eth0","root":true}]"#,
            root.path(),
        )
        .unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().to_owned(),
        });

        let readings = collector
            .translate_qdisc_rows(rows)
            .unwrap_or_else(|error| panic!("{}", error.message));

        assert_eq!(readings.len(), QDISC_METRICS_PER_ROW);
        for metric in [
            "linux.tc.max_packet_bytes",
            "linux.tc.drop_overlimit",
            "linux.tc.new_flow_count",
            "linux.tc.ecn_marks",
            "linux.tc.new_flows_len",
            "linux.tc.old_flows_len",
        ] {
            let reading = readings
                .iter()
                .find(|reading| reading.metric().as_str() == metric)
                .unwrap();
            assert!(matches!(
                reading.outcome(),
                ReadingOutcome::Unavailable(UnavailableReason::Missing)
            ));
        }
    }

    #[test]
    fn extended_statistics_are_retained_when_another_qdisc_exports_them() {
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        let rows = tc::parse_qdiscs_for_test(
            br#"[{"kind":"fq","handle":"1:","dev":"eth0","root":true,"maxpacket":900}]"#,
            root.path(),
        )
        .unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().to_owned(),
        });

        let readings = collector
            .translate_qdisc_rows(rows)
            .unwrap_or_else(|error| panic!("{}", error.message));

        assert_eq!(readings.len(), QDISC_METRICS_PER_ROW);
        let maximum = readings
            .iter()
            .find(|reading| reading.metric().as_str() == "linux.tc.max_packet_bytes")
            .unwrap();
        assert!(matches!(
            maximum.outcome(),
            ReadingOutcome::Observed(MetricReading::Gauge(900))
        ));
    }

    fn nft_ruleset(rules: Vec<netfilter::NetfilterRule>) -> netfilter::NetfilterRuleset {
        netfilter::NetfilterRuleset {
            backend: netfilter::NetfilterBackend::Nftables,
            tables: vec![netfilter::NetfilterTable {
                family: Some(netfilter::NftFamily::Inet),
                name: "fw4".to_owned(),
                handle: Some(1),
                chains: vec![netfilter::NetfilterChain {
                    name: "input".to_owned(),
                    handle: Some(2),
                    chain_type: Some("filter".to_owned()),
                    hook: Some(netfilter::NetfilterHook::Input),
                    priority: Some(0),
                    policy: Some(netfilter::ChainPolicy::Drop),
                    counters: None,
                    rules,
                }],
                named_counters: Vec::new(),
            }],
            nft_metadata: None,
        }
    }

    fn nft_rule(
        summary: &str,
        verdict: netfilter::RuleVerdict,
        counters: Option<(u64, u64)>,
    ) -> netfilter::NetfilterRule {
        netfilter::NetfilterRule {
            handle: None,
            fingerprint: netfilter::RuleFingerprint::from_stable_identity(summary),
            counters: counters.map(|(packets, bytes)| netfilter::RuleCounters { packets, bytes }),
            counter_reference: None,
            actions: vec![netfilter::RuleAction::Verdict(verdict)],
            summary: summary.to_owned(),
        }
    }

    fn rule_row_id(readings: &[SampleReading], expression: &str) -> String {
        readings
            .iter()
            .find(|reading| {
                reading.metric().as_str() == "linux.netfilter.rule.expression"
                    && matches!(
                        reading.outcome(),
                        ReadingOutcome::Observed(MetricReading::State(value))
                            if value.as_str() == expression
                    )
            })
            .and_then(|reading| reading.labels().get(MetricLabel::RowId))
            .unwrap()
            .to_owned()
    }

    #[test]
    fn netfilter_translation_keeps_counterless_rules_visible_without_zeroes() {
        let root = tempdir().unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        });
        let ruleset = nft_ruleset(vec![
            nft_rule(
                "tcp dport 443 accept",
                netfilter::RuleVerdict::Accept,
                Some((12, 960)),
            ),
            nft_rule("tcp dport 23 reject", netfilter::RuleVerdict::Reject, None),
        ]);

        let translated = collector
            .translate_netfilter_ruleset(&ruleset)
            .unwrap_or_else(|error| panic!("{}", error.message));

        assert!(translated.warning.is_none());
        assert_eq!(translated.readings.len(), 11);
        let counterless = translated
            .readings
            .iter()
            .find(|reading| {
                reading.metric().as_str() == "linux.netfilter.rule.packets"
                    && reading.labels().get(MetricLabel::Verdict) == Some("reject")
            })
            .unwrap();
        assert!(matches!(
            counterless.outcome(),
            ReadingOutcome::Unavailable(UnavailableReason::Missing)
        ));
        assert_eq!(
            counterless.labels().get(MetricLabel::Backend),
            Some("nftables")
        );
        assert_eq!(counterless.labels().get(MetricLabel::Family), Some("inet"));
    }

    #[test]
    fn netfilter_rule_identity_survives_an_insertion_before_it() {
        let root = tempdir().unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        });
        let first = nft_ruleset(vec![nft_rule(
            "existing accept",
            netfilter::RuleVerdict::Accept,
            Some((10, 100)),
        )]);
        let first = collector
            .translate_netfilter_ruleset(&first)
            .unwrap_or_else(|error| panic!("{}", error.message));
        let existing_row_id = rule_row_id(&first.readings, "existing accept");

        let second = nft_ruleset(vec![
            nft_rule("new drop", netfilter::RuleVerdict::Drop, Some((1, 10))),
            nft_rule(
                "existing accept",
                netfilter::RuleVerdict::Accept,
                Some((12, 120)),
            ),
        ]);
        let second = collector
            .translate_netfilter_ruleset(&second)
            .unwrap_or_else(|error| panic!("{}", error.message));

        assert_eq!(
            rule_row_id(&second.readings, "existing accept"),
            existing_row_id
        );
        let position = second
            .readings
            .iter()
            .find(|reading| {
                reading.metric().as_str() == "linux.netfilter.rule.position"
                    && reading.labels().get(MetricLabel::RowId) == Some(existing_row_id.as_str())
            })
            .unwrap();
        assert!(matches!(
            position.outcome(),
            ReadingOutcome::Observed(MetricReading::Gauge(2))
        ));
    }

    #[test]
    fn netfilter_translation_reports_rule_cardinality_as_partial() {
        let root = tempdir().unwrap();
        let mut collector = BuiltinCollector::new(SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        });
        let rules = (0..1_100)
            .map(|index| {
                nft_rule(
                    &format!("rule {index} accept"),
                    netfilter::RuleVerdict::Accept,
                    Some((index, index * 10)),
                )
            })
            .collect();

        let translated = collector
            .translate_netfilter_ruleset(&nft_ruleset(rules))
            .unwrap_or_else(|error| panic!("{}", error.message));

        assert_eq!(translated.readings.len(), 4_095);
        assert!(translated.warning.is_some_and(|warning| {
            warning.code() == MonitorErrorCode::CardinalityLimit
                && warning.diagnostic().contains("1023/1100 rules")
        }));
    }

    #[test]
    fn advertises_unimplemented_source_families_as_unsupported() {
        let session_start = Instant::now();
        let mut samples = Vec::new();
        add_unsupported_samples(&mut samples, session_start);

        assert!(!samples
            .iter()
            .any(|sample| sample.provider().as_str() == TC_NETLINK));
        {
            let expected = "linux.ethtool.netlink";
            let sample = samples
                .iter()
                .find(|sample| sample.provider().as_str() == expected)
                .unwrap();
            assert!(matches!(
                sample.health(),
                ProviderHealth::Unsupported { .. }
            ));
            assert!(sample.readings().is_empty());
        }
    }

    #[test]
    fn sanitizes_and_bounds_provider_diagnostics() {
        let error = monitor_error(MonitorErrorCode::Io, format!("bad\n{}", "x".repeat(300)));

        assert!(error.diagnostic().is_ascii());
        assert!(!error.diagnostic().contains('\n'));
        assert_eq!(
            error.diagnostic().len(),
            super::super::model::MAX_DIAGNOSTIC_BYTES
        );
    }
}
