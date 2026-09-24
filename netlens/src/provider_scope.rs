use std::collections::BTreeSet;

use anyhow::Context;

use crate::capture::{
    EffectiveInterfaceScope, EffectiveNetworkNamespace, EffectiveScope, FlowFilter,
    ProviderFilterSupport, ProviderScope, RequestedScope,
};
use crate::model::NamespacedName;
use crate::provider::{
    self as provider_registry, DirectionScope, InterfaceScope, NetworkNamespaceScope,
    ProviderActivation, ProviderDescriptor,
};

pub fn selected_providers(requested: &RequestedScope) -> BTreeSet<&'static str> {
    provider_registry::capture_descriptors()
        .filter(|provider| {
            provider
                .owned_layers
                .iter()
                .any(|owned| requested.layers.contains(&owned.layer))
        })
        .map(|provider| provider.name)
        .collect()
}

pub fn for_report(
    requested: &RequestedScope,
    ready_event_providers: &BTreeSet<&'static str>,
) -> anyhow::Result<Vec<ProviderScope>> {
    let mut scopes = provider_registry::capture_descriptors()
        .map(|provider| scope_for(provider, requested, ready_event_providers))
        .collect::<anyhow::Result<Vec<_>>>()?;
    scopes.sort_by(|left, right| left.provider.cmp(&right.provider));
    Ok(scopes)
}

fn scope_for(
    provider: &ProviderDescriptor,
    requested: &RequestedScope,
    ready_event_providers: &BTreeSet<&'static str>,
) -> anyhow::Result<ProviderScope> {
    let scope = provider
        .scope
        .expect("capture providers have a scope descriptor");
    let interface_path_complete = requested
        .interface_path
        .as_ref()
        .is_none_or(|path| path.is_complete());
    let filter_support = scope.filter_support(interface_path_complete);
    let inactive = match scope.activation {
        ProviderActivation::Always => false,
        ProviderActivation::RuntimeReady => !ready_event_providers.contains(provider.name),
        ProviderActivation::NotImplemented => true,
    };
    if inactive {
        return ProviderScope::unavailable(
            provider_name(provider.name)?,
            requested.clone(),
            filter_support,
        )
        .context("construct inactive provider scope");
    }

    let network_namespace = match scope.network_namespace {
        NetworkNamespaceScope::Current => EffectiveNetworkNamespace::Current {
            identity: requested.network_namespace.identity.clone(),
        },
        NetworkNamespaceScope::HostWide => EffectiveNetworkNamespace::HostWide,
    };
    let interface_scope = match scope.interface {
        InterfaceScope::AllVisible => EffectiveInterfaceScope::AllVisible,
        InterfaceScope::RequestedPathWhenComplete if interface_path_complete => requested
            .interface_path
            .clone()
            .map_or(EffectiveInterfaceScope::AllVisible, |path| {
                EffectiveInterfaceScope::Path { path }
            }),
        InterfaceScope::RequestedPathWhenComplete => EffectiveInterfaceScope::AllVisible,
    };
    let direction = match scope.direction {
        DirectionScope::Unspecified => None,
        DirectionScope::Requested => requested.direction,
    };

    active_or_unavailable(
        provider,
        requested,
        filter_support,
        network_namespace,
        interface_scope,
        direction,
    )
}

fn active_or_unavailable(
    provider: &ProviderDescriptor,
    requested: &RequestedScope,
    filter_support: ProviderFilterSupport,
    network_namespace: EffectiveNetworkNamespace,
    interface_scope: EffectiveInterfaceScope,
    direction: Option<crate::model::Direction>,
) -> anyhow::Result<ProviderScope> {
    let layers: BTreeSet<_> = provider
        .owned_layer_ids()
        .filter(|layer| requested.layers.contains(layer))
        .collect();
    let provider = provider_name(provider.name)?;
    if layers.is_empty() {
        return ProviderScope::unavailable(provider, requested.clone(), filter_support)
            .context("construct out-of-scope provider scope");
    }
    ProviderScope::active(
        provider,
        requested.clone(),
        EffectiveScope {
            layers,
            network_namespace,
            interface_scope,
            direction,
            flow: FlowFilter::default(),
        },
        filter_support,
    )
    .context("construct effective provider scope")
}

fn provider_name(provider: &str) -> anyhow::Result<NamespacedName> {
    NamespacedName::new(provider).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::capture::{
        CaptureDuration, CapturePlan, CurrentNetworkNamespace, InterfaceAnchor, InterfacePath,
        TopologyGap,
    };
    use crate::model::{
        FilterSupport, Layer, PROVIDER_KFREE_SKB, PROVIDER_LINK, PROVIDER_PROC_PROTOCOL,
        PROVIDER_SOCKET_RECEIVE_QUEUE_FULL, PROVIDER_SOCK_DIAG, PROVIDER_SOFTNET,
        PROVIDER_UDP_RECEIVE_ADMISSION,
    };

    use super::*;

    #[test]
    fn provider_layers_are_owned_subsets_not_copies_of_the_request() {
        let mut plan = CapturePlan::new(
            CaptureDuration::new(Duration::ZERO).unwrap(),
            CurrentNetworkNamespace::unknown(),
        );
        plan.layers = [Layer::Netfilter, Layer::Netdevice, Layer::Driver]
            .into_iter()
            .collect();
        let requested = plan.requested_scope().unwrap();

        let scopes = for_report(&requested, &BTreeSet::new()).unwrap();
        let link = scopes
            .iter()
            .find(|scope| scope.provider.as_str() == PROVIDER_LINK)
            .unwrap();

        assert_eq!(
            link.effective.as_ref().unwrap().layers,
            BTreeSet::from([Layer::Netdevice, Layer::Driver])
        );
    }

    #[test]
    fn provider_selection_follows_requested_layers() {
        let mut plan = CapturePlan::new(
            CaptureDuration::new(Duration::ZERO).unwrap(),
            CurrentNetworkNamespace::unknown(),
        );
        plan.layers = [Layer::Nic].into_iter().collect();
        let nic = selected_providers(&plan.requested_scope().unwrap());
        assert_eq!(nic, BTreeSet::from([PROVIDER_LINK]));

        plan.layers = [Layer::Netfilter].into_iter().collect();
        let netfilter = selected_providers(&plan.requested_scope().unwrap());
        assert_eq!(netfilter, BTreeSet::from([PROVIDER_KFREE_SKB]));
    }

    #[test]
    fn every_v5_layer_selects_exactly_its_registered_providers() {
        for (layer, expected) in [
            (
                Layer::Socket,
                BTreeSet::from([
                    PROVIDER_KFREE_SKB,
                    PROVIDER_PROC_PROTOCOL,
                    PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
                    PROVIDER_SOCK_DIAG,
                    PROVIDER_UDP_RECEIVE_ADMISSION,
                ]),
            ),
            (
                Layer::Transport,
                BTreeSet::from([PROVIDER_KFREE_SKB, PROVIDER_PROC_PROTOCOL]),
            ),
            (
                Layer::Network,
                BTreeSet::from([PROVIDER_KFREE_SKB, PROVIDER_PROC_PROTOCOL]),
            ),
            (Layer::Netfilter, BTreeSet::from([PROVIDER_KFREE_SKB])),
            (
                Layer::Route,
                BTreeSet::from([PROVIDER_KFREE_SKB, PROVIDER_PROC_PROTOCOL]),
            ),
            (Layer::Xfrm, BTreeSet::from([PROVIDER_KFREE_SKB])),
            (Layer::VirtualDevice, BTreeSet::from([PROVIDER_KFREE_SKB])),
            (Layer::Tc, BTreeSet::from([PROVIDER_KFREE_SKB])),
            (
                Layer::Netdevice,
                BTreeSet::from([PROVIDER_KFREE_SKB, PROVIDER_LINK, PROVIDER_SOFTNET]),
            ),
            (Layer::Xdp, BTreeSet::from([PROVIDER_KFREE_SKB])),
            (Layer::Driver, BTreeSet::from([PROVIDER_LINK])),
            (Layer::Nic, BTreeSet::from([PROVIDER_LINK])),
            (Layer::KernelBypass, BTreeSet::new()),
        ] {
            let mut plan = CapturePlan::new(
                CaptureDuration::new(Duration::ZERO).unwrap(),
                CurrentNetworkNamespace::unknown(),
            );
            plan.layers = [layer].into_iter().collect();
            assert_eq!(
                selected_providers(&plan.requested_scope().unwrap()),
                expected,
                "{} selection differs from the v5 registry",
                layer.as_str()
            );
        }
    }

    #[test]
    fn interface_anchor_keeps_kfree_selected_with_a_broader_scope() {
        let mut plan = CapturePlan::new(
            CaptureDuration::new(Duration::ZERO).unwrap(),
            CurrentNetworkNamespace::unknown(),
        );
        plan.layers = [Layer::Netfilter].into_iter().collect();
        plan.interface_path = Some(
            InterfacePath::new(
                InterfaceAnchor::indexed(1).unwrap(),
                Some(crate::model::IfIndex::new(1).unwrap()),
                [crate::model::IfIndex::new(1).unwrap()],
                [TopologyGap::DynamicRedirect],
            )
            .unwrap(),
        );
        let requested = plan.requested_scope().unwrap();

        assert!(selected_providers(&requested).contains(PROVIDER_KFREE_SKB));
        let scopes = for_report(&requested, &BTreeSet::from([PROVIDER_KFREE_SKB])).unwrap();
        let kfree = scopes
            .iter()
            .find(|scope| scope.provider.as_str() == PROVIDER_KFREE_SKB)
            .unwrap();
        let effective = kfree.effective.as_ref().unwrap();
        assert_eq!(
            effective.network_namespace,
            EffectiveNetworkNamespace::HostWide
        );
        assert_eq!(
            effective.interface_scope,
            EffectiveInterfaceScope::AllVisible
        );
    }

    #[test]
    fn registry_scope_profiles_preserve_filter_and_activation_behavior() {
        let mut plan = CapturePlan::new(
            CaptureDuration::new(Duration::ZERO).unwrap(),
            CurrentNetworkNamespace::unknown(),
        );
        plan.layers = [Layer::Netdevice].into_iter().collect();
        let ready = BTreeSet::from([PROVIDER_KFREE_SKB]);
        let no_path = for_report(&plan.requested_scope().unwrap(), &ready).unwrap();
        let link = no_path
            .iter()
            .find(|scope| scope.provider.as_str() == PROVIDER_LINK)
            .unwrap();
        assert_eq!(
            link.filter_support.interface_path,
            FilterSupport::UserspaceExact
        );

        plan.interface_path = Some(
            InterfacePath::new(
                InterfaceAnchor::indexed(1).unwrap(),
                Some(crate::model::IfIndex::new(1).unwrap()),
                [crate::model::IfIndex::new(1).unwrap()],
                [TopologyGap::DynamicRedirect],
            )
            .unwrap(),
        );
        let incomplete = for_report(&plan.requested_scope().unwrap(), &ready).unwrap();
        let link = incomplete
            .iter()
            .find(|scope| scope.provider.as_str() == PROVIDER_LINK)
            .unwrap();
        assert_eq!(
            link.filter_support.interface_path,
            FilterSupport::BroaderOnly
        );
        assert_eq!(
            link.effective.as_ref().unwrap().interface_scope,
            EffectiveInterfaceScope::AllVisible
        );

        let not_ready = for_report(&plan.requested_scope().unwrap(), &BTreeSet::new()).unwrap();
        assert!(not_ready
            .iter()
            .find(|scope| scope.provider.as_str() == PROVIDER_KFREE_SKB)
            .unwrap()
            .effective
            .is_none());
    }

    #[test]
    fn event_scopes_activate_only_from_their_provider_key() {
        let mut plan = CapturePlan::new(
            CaptureDuration::new(Duration::ZERO).unwrap(),
            CurrentNetworkNamespace::unknown(),
        );
        plan.layers = [Layer::Socket].into_iter().collect();
        let requested = plan.requested_scope().unwrap();

        let scopes = for_report(&requested, &BTreeSet::from([PROVIDER_KFREE_SKB])).unwrap();
        assert!(scopes
            .iter()
            .find(|scope| scope.provider.as_str() == PROVIDER_KFREE_SKB)
            .unwrap()
            .effective
            .is_some());
        for provider in [
            PROVIDER_UDP_RECEIVE_ADMISSION,
            PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
        ] {
            let scope = scopes
                .iter()
                .find(|scope| scope.provider.as_str() == provider)
                .unwrap();
            assert!(
                scope.effective.is_none(),
                "{provider} activated from kfree ready"
            );
            assert_eq!(
                scope.filter_support.network_namespace,
                FilterSupport::BroaderOnly
            );
            assert_eq!(
                scope.filter_support.interface_path,
                FilterSupport::BroaderOnly
            );
        }
    }
}
