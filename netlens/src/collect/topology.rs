use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::Path;

use anyhow::{anyhow, bail, Context};

use crate::capture::{InterfaceAnchor, InterfacePath, TopologyGap};
use crate::model::IfIndex;

use super::valid_interface_name;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedInterfacePath {
    pub path: InterfacePath,
    pub interface_names: BTreeSet<String>,
}

#[derive(Debug)]
struct InterfaceNode {
    ifindex: IfIndex,
    iflink: Option<u32>,
    linked_names: BTreeSet<String>,
    has_unresolved_link: bool,
}

pub fn resolve_interface_path(
    sys_root: &Path,
    anchor: InterfaceAnchor,
) -> anyhow::Result<ResolvedInterfacePath> {
    let nodes = read_nodes(&sys_root.join("class/net"))?;
    let by_ifindex: BTreeMap<_, _> = nodes
        .iter()
        .map(|(name, node)| (node.ifindex.get(), name.as_str()))
        .collect();
    let anchor_name = match &anchor {
        InterfaceAnchor::Name { name } => nodes
            .contains_key(name)
            .then_some(name.as_str())
            .ok_or_else(|| anyhow!("interface {name:?} is not visible in the current namespace"))?,
        InterfaceAnchor::Ifindex { ifindex } => {
            by_ifindex.get(&ifindex.get()).copied().ok_or_else(|| {
                anyhow!(
                    "interface ifindex {} is not visible in the current namespace",
                    ifindex.get()
                )
            })?
        }
    };

    let mut names = BTreeSet::new();
    let mut ifindices = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    let mut pending = VecDeque::from([anchor_name.to_owned()]);

    while let Some(name) = pending.pop_front() {
        if !names.insert(name.clone()) {
            continue;
        }
        let node = nodes
            .get(&name)
            .expect("topology queue contains only discovered interfaces");
        ifindices.insert(node.ifindex);
        if node.has_unresolved_link {
            gaps.insert(TopologyGap::LowerDeviceUnresolved);
        }
        for linked_name in &node.linked_names {
            if nodes.contains_key(linked_name) {
                pending.push_back(linked_name.clone());
            } else {
                gaps.insert(TopologyGap::LowerDeviceUnresolved);
            }
        }
        if let Some(iflink) = node.iflink.filter(|iflink| *iflink != node.ifindex.get()) {
            if let Some(linked_name) = by_ifindex.get(&iflink) {
                pending.push_back((*linked_name).to_owned());
            } else {
                gaps.insert(TopologyGap::CrossNamespace);
            }
        }
    }

    // Current topology discovery has no TC/XDP program inventory, so a
    // runtime redirect can leave the static sysfs closure.
    gaps.insert(TopologyGap::DynamicRedirect);

    let resolved_anchor_ifindex = nodes.get(anchor_name).map(|node| node.ifindex);
    let path = InterfacePath::new(anchor, resolved_anchor_ifindex, ifindices, gaps)
        .context("construct interface path anchor closure")?;
    Ok(ResolvedInterfacePath {
        path,
        interface_names: names,
    })
}

fn read_nodes(net_root: &Path) -> anyhow::Result<BTreeMap<String, InterfaceNode>> {
    let entries = fs::read_dir(net_root)
        .with_context(|| format!("{}: cannot list interfaces", net_root.display()))?;
    let mut nodes = BTreeMap::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("{}: invalid directory entry", net_root.display()))
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if !valid_interface_name(&name) {
            continue;
        }
        let node = read_node(&entry.path());
        let InterfaceNode {
            ifindex,
            iflink,
            linked_names,
            has_unresolved_link,
        } = match node {
            Ok(node) => node,
            Err(error) if is_not_found(&error) => continue,
            Err(error) => return Err(error),
        };
        if nodes
            .insert(
                name.clone(),
                InterfaceNode {
                    ifindex,
                    iflink,
                    linked_names,
                    has_unresolved_link,
                },
            )
            .is_some()
        {
            bail!("duplicate interface name {name:?} in sysfs");
        }
    }
    if nodes.is_empty() {
        bail!("{} contains no visible interfaces", net_root.display());
    }
    let mut seen_ifindices = BTreeSet::new();
    for node in nodes.values() {
        if !seen_ifindices.insert(node.ifindex) {
            bail!(
                "duplicate interface ifindex {} in sysfs",
                node.ifindex.get()
            );
        }
    }
    Ok(nodes)
}

fn read_node(path: &Path) -> anyhow::Result<InterfaceNode> {
    let ifindex = read_u32(&path.join("ifindex"))?;
    let ifindex = IfIndex::new(ifindex).map_err(|error| anyhow!(error))?;
    let iflink = read_optional_u32(&path.join("iflink"))?;
    let (linked_names, has_unresolved_link) = read_named_links(path)?;
    Ok(InterfaceNode {
        ifindex,
        iflink,
        linked_names,
        has_unresolved_link,
    })
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn read_named_links(path: &Path) -> anyhow::Result<(BTreeSet<String>, bool)> {
    let entries = fs::read_dir(path)
        .with_context(|| format!("{}: cannot inspect interface topology", path.display()))?;
    let mut names = BTreeSet::new();
    let mut unresolved = false;
    for entry in entries {
        let entry = entry.with_context(|| format!("{}: invalid topology entry", path.display()))?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let linked_name = file_name
            .strip_prefix("lower_")
            .or_else(|| file_name.strip_prefix("upper_"));
        let Some(linked_name) = linked_name else {
            continue;
        };
        if valid_interface_name(linked_name) {
            names.insert(linked_name.to_owned());
        } else {
            unresolved = true;
        }
    }
    Ok((names, unresolved))
}

fn read_u32(path: &Path) -> anyhow::Result<u32> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("{}: cannot read unsigned integer", path.display()))?;
    value
        .trim()
        .parse()
        .with_context(|| format!("{} is not an unsigned integer", path.display()))
}

fn read_optional_u32(path: &Path) -> anyhow::Result<Option<u32>> {
    match fs::read_to_string(path) {
        Ok(value) => value
            .trim()
            .parse()
            .map(Some)
            .with_context(|| format!("{} is not an unsigned integer", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("{}: cannot read unsigned integer", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn add_interface(root: &Path, name: &str, ifindex: u32, iflink: u32) {
        let path = root.join("class/net").join(name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("ifindex"), format!("{ifindex}\n")).unwrap();
        fs::write(path.join("iflink"), format!("{iflink}\n")).unwrap();
    }

    #[test]
    fn resolves_visible_lower_and_iflink_closure() {
        let root = tempdir().unwrap();
        add_interface(root.path(), "eth0", 2, 2);
        add_interface(root.path(), "vlan10", 3, 2);
        fs::create_dir(root.path().join("class/net/vlan10/lower_eth0")).unwrap();
        fs::create_dir(root.path().join("class/net/eth0/upper_vlan10")).unwrap();

        let resolved =
            resolve_interface_path(root.path(), InterfaceAnchor::named("vlan10").unwrap()).unwrap();

        assert_eq!(
            resolved.interface_names,
            BTreeSet::from(["eth0".to_owned(), "vlan10".to_owned()])
        );
        assert_eq!(
            resolved
                .path
                .visible_ifindices
                .iter()
                .map(|value| value.get())
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(
            resolved.path.topology_gaps,
            BTreeSet::from([TopologyGap::DynamicRedirect])
        );
    }

    #[test]
    fn marks_an_iflink_outside_the_visible_namespace() {
        let root = tempdir().unwrap();
        add_interface(root.path(), "veth0", 4, 99);

        let resolved =
            resolve_interface_path(root.path(), InterfaceAnchor::indexed(4).unwrap()).unwrap();

        assert_eq!(
            resolved.interface_names,
            BTreeSet::from(["veth0".to_owned()])
        );
        assert_eq!(
            resolved.path.resolved_anchor_ifindex.map(IfIndex::get),
            Some(4)
        );
        assert_eq!(
            resolved.path.topology_gaps,
            BTreeSet::from([TopologyGap::DynamicRedirect, TopologyGap::CrossNamespace])
        );
    }

    #[test]
    fn rejects_an_anchor_outside_the_current_namespace() {
        let root = tempdir().unwrap();
        add_interface(root.path(), "lo", 1, 1);

        let error =
            resolve_interface_path(root.path(), InterfaceAnchor::named("missing0").unwrap())
                .unwrap_err();

        assert!(error.to_string().contains("not visible"));
    }

    #[test]
    fn ignores_an_unrelated_interface_that_disappeared_during_discovery() {
        let root = tempdir().unwrap();
        add_interface(root.path(), "lo", 1, 1);
        fs::create_dir_all(root.path().join("class/net/gone0")).unwrap();

        let resolved =
            resolve_interface_path(root.path(), InterfaceAnchor::named("lo").unwrap()).unwrap();

        assert_eq!(resolved.interface_names, BTreeSet::from(["lo".to_owned()]));
    }
}
