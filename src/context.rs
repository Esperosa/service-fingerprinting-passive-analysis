use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::PathBuf,
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::{BakulaError, Result},
    model::{Confidence, HostReport, MonitoringLane, NetworkAsset, Severity, TopologyEdge},
};

#[derive(Debug, Clone, Default)]
pub struct ContextConfig {
    pub snmp_snapshot: Option<PathBuf>,
    pub librenms_snapshot: Option<PathBuf>,
    pub librenms_base_url: Option<String>,
    pub librenms_token_env: String,
    pub meraki_snapshot: Option<PathBuf>,
    pub meraki_api_key_env: String,
    pub meraki_network_id: Option<String>,
    pub meraki_timespan_seconds: u32,
    pub unifi_snapshot: Option<PathBuf>,
    pub unifi_devices_url: Option<String>,
    pub unifi_clients_url: Option<String>,
    pub unifi_links_url: Option<String>,
    pub unifi_api_key_env: String,
    pub aruba_snapshot: Option<PathBuf>,
    pub aruba_base_url: Option<String>,
    pub aruba_token_env: String,
    pub aruba_site_id: Option<String>,
    pub omada_snapshot: Option<PathBuf>,
    pub omada_devices_url: Option<String>,
    pub omada_clients_url: Option<String>,
    pub omada_links_url: Option<String>,
    pub omada_access_token_env: String,
}

#[derive(Debug, Clone, Default)]
pub struct ContextArtifacts {
    pub snmp_snapshot_json: Option<String>,
    pub librenms_snapshot_json: Option<String>,
    pub meraki_snapshot_json: Option<String>,
    pub unifi_snapshot_json: Option<String>,
    pub aruba_snapshot_json: Option<String>,
    pub omada_snapshot_json: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ContextBundle {
    pub network_assets: Vec<NetworkAsset>,
    pub topology_edges: Vec<TopologyEdge>,
    pub monitoring_lanes: Vec<MonitoringLane>,
    pub artifacts: ContextArtifacts,
}

pub fn collect_context(hosts: &[HostReport], config: &ContextConfig) -> Result<ContextBundle> {
    let mut assets = BTreeMap::<String, NetworkAsset>::new();
    let mut edges = BTreeMap::<String, TopologyEdge>::new();
    let mut lanes = Vec::<MonitoringLane>::new();
    let mut artifacts = ContextArtifacts::default();

    if let Some(snapshot_path) = &config.snmp_snapshot {
        let raw = fs::read_to_string(snapshot_path)?;
        let snapshot: SnmpTopologySnapshot = serde_json::from_str(&raw)?;
        artifacts.snmp_snapshot_json = Some(raw);
        let normalized = snmp_to_snapshot(snapshot);
        merge_normalized_snapshot(hosts, "snmp", normalized.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "snmp",
            "context",
            "SNMP + LLDP/CDP + ARP/FDB",
            &normalized,
        ));
    }

    if let Some(snapshot_path) = &config.librenms_snapshot {
        let raw = fs::read_to_string(snapshot_path)?;
        let snapshot: NormalizedControllerSnapshot = serde_json::from_str(&raw)?;
        artifacts.librenms_snapshot_json = Some(raw);
        merge_normalized_snapshot(hosts, "librenms", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "librenms",
            "context",
            "LibreNMS visibility",
            &snapshot,
        ));
    } else if let Some(base_url) = &config.librenms_base_url {
        let snapshot = fetch_librenms_snapshot(base_url, &config.librenms_token_env)?;
        artifacts.librenms_snapshot_json =
            Some(serde_json::to_string_pretty(&snapshot).map_err(BakulaError::Json)?);
        merge_normalized_snapshot(hosts, "librenms", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "librenms",
            "context",
            "LibreNMS visibility",
            &snapshot,
        ));
    }

    if let Some(snapshot_path) = &config.meraki_snapshot {
        let raw = fs::read_to_string(snapshot_path)?;
        let snapshot: MerakiSnapshot = serde_json::from_str(&raw)?;
        artifacts.meraki_snapshot_json = Some(raw);
        let normalized = meraki_to_snapshot(snapshot);
        merge_normalized_snapshot(hosts, "meraki", normalized.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "meraki",
            "context",
            "Meraki controller",
            &normalized,
        ));
    } else if let Some(network_id) = &config.meraki_network_id {
        let snapshot = fetch_meraki_snapshot(
            network_id,
            &config.meraki_api_key_env,
            config.meraki_timespan_seconds,
        )?;
        artifacts.meraki_snapshot_json =
            Some(serde_json::to_string_pretty(&snapshot).map_err(BakulaError::Json)?);
        let normalized = meraki_to_snapshot(snapshot);
        merge_normalized_snapshot(hosts, "meraki", normalized.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "meraki",
            "context",
            "Meraki controller",
            &normalized,
        ));
    }

    if let Some(snapshot_path) = &config.unifi_snapshot {
        let raw = fs::read_to_string(snapshot_path)?;
        let snapshot: NormalizedControllerSnapshot = serde_json::from_str(&raw)?;
        artifacts.unifi_snapshot_json = Some(raw);
        merge_normalized_snapshot(hosts, "unifi", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "unifi",
            "context",
            "UniFi controller",
            &snapshot,
        ));
    } else if config.unifi_devices_url.is_some() || config.unifi_clients_url.is_some() {
        let snapshot = fetch_generic_controller_snapshot(
            "unifi",
            &config.unifi_api_key_env,
            config.unifi_devices_url.as_deref(),
            config.unifi_clients_url.as_deref(),
            config.unifi_links_url.as_deref(),
        )?;
        artifacts.unifi_snapshot_json =
            Some(serde_json::to_string_pretty(&snapshot).map_err(BakulaError::Json)?);
        merge_normalized_snapshot(hosts, "unifi", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "unifi",
            "context",
            "UniFi controller",
            &snapshot,
        ));
    }

    if let Some(snapshot_path) = &config.aruba_snapshot {
        let raw = fs::read_to_string(snapshot_path)?;
        let snapshot: NormalizedControllerSnapshot = serde_json::from_str(&raw)?;
        artifacts.aruba_snapshot_json = Some(raw);
        merge_normalized_snapshot(hosts, "aruba", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane("aruba", "context", "Aruba Central", &snapshot));
    } else if let (Some(base_url), Some(site_id)) = (&config.aruba_base_url, &config.aruba_site_id)
    {
        let snapshot = fetch_aruba_snapshot(base_url, &config.aruba_token_env, site_id)?;
        artifacts.aruba_snapshot_json =
            Some(serde_json::to_string_pretty(&snapshot).map_err(BakulaError::Json)?);
        merge_normalized_snapshot(hosts, "aruba", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane("aruba", "context", "Aruba Central", &snapshot));
    }

    if let Some(snapshot_path) = &config.omada_snapshot {
        let raw = fs::read_to_string(snapshot_path)?;
        let snapshot: NormalizedControllerSnapshot = serde_json::from_str(&raw)?;
        artifacts.omada_snapshot_json = Some(raw);
        merge_normalized_snapshot(hosts, "omada", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "omada",
            "context",
            "Omada controller",
            &snapshot,
        ));
    } else if config.omada_devices_url.is_some() || config.omada_clients_url.is_some() {
        let snapshot = fetch_generic_controller_snapshot(
            "omada",
            &config.omada_access_token_env,
            config.omada_devices_url.as_deref(),
            config.omada_clients_url.as_deref(),
            config.omada_links_url.as_deref(),
        )?;
        artifacts.omada_snapshot_json =
            Some(serde_json::to_string_pretty(&snapshot).map_err(BakulaError::Json)?);
        merge_normalized_snapshot(hosts, "omada", snapshot.clone(), &mut assets, &mut edges);
        lanes.push(build_lane(
            "omada",
            "context",
            "Omada controller",
            &snapshot,
        ));
    }

    Ok(ContextBundle {
        network_assets: assets.into_values().collect(),
        topology_edges: edges.into_values().collect(),
        monitoring_lanes: lanes,
        artifacts,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SnmpTopologySnapshot {
    #[serde(default)]
    devices: Vec<SnmpDevice>,
    #[serde(default)]
    neighbors: Vec<SnmpNeighbor>,
    #[serde(default)]
    vlans: Vec<NormalizedVlan>,
    #[serde(default)]
    arp: Vec<NormalizedArp>,
    #[serde(default)]
    fdb: Vec<NormalizedFdb>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnmpDevice {
    id: String,
    name: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    device_type: Option<String>,
    #[serde(default)]
    observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnmpNeighbor {
    local_device_id: String,
    #[serde(default)]
    remote_device_id: Option<String>,
    #[serde(default)]
    remote_name: Option<String>,
    #[serde(default)]
    remote_ip: Option<String>,
    #[serde(default)]
    local_port: Option<String>,
    #[serde(default)]
    remote_port: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MerakiSnapshot {
    #[serde(default)]
    devices: Vec<MerakiDevice>,
    #[serde(default)]
    clients: Vec<MerakiClient>,
    #[serde(default)]
    lldp_cdp: HashMap<String, Vec<MerakiLldpNeighbor>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerakiDevice {
    #[serde(default)]
    serial: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    lan_ip: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    product_type: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerakiClient {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    manufacturer: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    recent_device_name: Option<String>,
    #[serde(default)]
    recent_device_serial: Option<String>,
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    vlan: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerakiLldpNeighbor {
    #[serde(default)]
    source_port: Option<String>,
    #[serde(default)]
    remote_device_name: Option<String>,
    #[serde(default)]
    remote_device_serial: Option<String>,
    #[serde(default)]
    remote_port: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NormalizedControllerSnapshot {
    #[serde(default)]
    devices: Vec<NormalizedDevice>,
    #[serde(default)]
    clients: Vec<NormalizedClient>,
    #[serde(default)]
    links: Vec<NormalizedLink>,
    #[serde(default)]
    vlans: Vec<NormalizedVlan>,
    #[serde(default)]
    arp: Vec<NormalizedArp>,
    #[serde(default)]
    fdb: Vec<NormalizedFdb>,
    #[serde(default)]
    alerts: Vec<NormalizedAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedDevice {
    id: String,
    name: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    device_type: Option<String>,
    #[serde(default)]
    observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedClient {
    id: String,
    name: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    vlan: Option<String>,
    #[serde(default)]
    attached_device_id: Option<String>,
    #[serde(default)]
    observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedLink {
    source_id: String,
    target_id: String,
    relation: String,
    #[serde(default)]
    source_port: Option<String>,
    #[serde(default)]
    target_port: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    confidence: Option<Confidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedVlan {
    device_id: String,
    #[serde(default)]
    vlan_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    port: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedArp {
    device_id: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    vlan: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedFdb {
    device_id: String,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    vlan: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedAlert {
    id: String,
    title: String,
    severity: Severity,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    details: Vec<String>,
}
fn snmp_to_snapshot(snapshot: SnmpTopologySnapshot) -> NormalizedControllerSnapshot {
    let devices = snapshot
        .devices
        .into_iter()
        .map(|device| NormalizedDevice {
            id: device.id,
            name: device.name,
            ip: device.ip,
            mac: device.mac,
            vendor: device.vendor,
            model: device.model,
            serial: device.serial,
            status: device.status,
            location: device.location,
            device_type: device.device_type,
            observations: device.observations,
        })
        .collect();
    let links = snapshot
        .neighbors
        .into_iter()
        .map(|neighbor| NormalizedLink {
            source_id: neighbor.local_device_id,
            target_id: neighbor.remote_device_id.unwrap_or_else(|| {
                format!(
                    "inferred:{}",
                    neighbor.remote_name.unwrap_or_else(|| neighbor
                        .remote_ip
                        .unwrap_or_else(|| "unknown".to_string()))
                )
            }),
            relation: neighbor
                .protocol
                .unwrap_or_else(|| "lldp".to_string())
                .to_lowercase(),
            source_port: neighbor.local_port,
            target_port: neighbor.remote_port,
            protocol: None,
            confidence: Some(Confidence::Medium),
        })
        .collect();
    NormalizedControllerSnapshot {
        devices,
        links,
        vlans: snapshot.vlans,
        arp: snapshot.arp,
        fdb: snapshot.fdb,
        ..Default::default()
    }
}

fn meraki_to_snapshot(snapshot: MerakiSnapshot) -> NormalizedControllerSnapshot {
    let mut normalized = NormalizedControllerSnapshot::default();
    for device in snapshot.devices {
        normalized.devices.push(NormalizedDevice {
            id: device.serial.clone(),
            name: device.name.unwrap_or_else(|| device.serial.clone()),
            ip: device.lan_ip,
            mac: device.mac,
            vendor: Some("Cisco Meraki".to_string()),
            model: device.model,
            serial: Some(device.serial.clone()),
            status: device.status,
            location: device.address,
            device_type: device.product_type,
            observations: device
                .tags
                .unwrap_or_default()
                .into_iter()
                .map(|tag| format!("tag={tag}"))
                .chain(device.notes.into_iter().map(|note| format!("notes={note}")))
                .collect(),
        });

        if let Some(neighbors) = snapshot.lldp_cdp.get(&device.serial) {
            for neighbor in neighbors {
                normalized.links.push(NormalizedLink {
                    source_id: device.serial.clone(),
                    target_id: neighbor.remote_device_serial.clone().unwrap_or_else(|| {
                        format!(
                            "inferred:{}",
                            neighbor
                                .remote_device_name
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string())
                        )
                    }),
                    relation: neighbor
                        .protocol
                        .clone()
                        .unwrap_or_else(|| "lldp".to_string())
                        .to_lowercase(),
                    source_port: neighbor.source_port.clone(),
                    target_port: neighbor.remote_port.clone(),
                    protocol: neighbor.protocol.clone(),
                    confidence: Some(Confidence::Medium),
                });
            }
        }
    }

    for client in snapshot.clients {
        normalized.clients.push(NormalizedClient {
            id: client
                .id
                .clone()
                .or_else(|| client.mac.clone())
                .or_else(|| client.ip.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            name: client
                .description
                .clone()
                .or_else(|| client.mac.clone())
                .unwrap_or_else(|| "Bez názvu".to_string()),
            ip: client.ip,
            mac: client.mac,
            vendor: client.manufacturer,
            model: client.os,
            status: client.status,
            ssid: client.ssid.clone(),
            vlan: client.vlan.clone(),
            attached_device_id: client.recent_device_serial,
            observations: vec![
                client
                    .ssid
                    .map(|ssid| format!("ssid={ssid}"))
                    .unwrap_or_else(|| "ssid=?".to_string()),
                client
                    .vlan
                    .map(|vlan| format!("vlan={vlan}"))
                    .unwrap_or_else(|| "vlan=?".to_string()),
                client
                    .recent_device_name
                    .map(|name| format!("ap_name={name}"))
                    .unwrap_or_else(|| "ap_name=?".to_string()),
            ],
        });
    }

    normalized
}

fn merge_normalized_snapshot(
    hosts: &[HostReport],
    source: &str,
    snapshot: NormalizedControllerSnapshot,
    assets: &mut BTreeMap<String, NetworkAsset>,
    edges: &mut BTreeMap<String, TopologyEdge>,
) {
    let mut known_device_ids = HashMap::<String, String>::new();

    for device in snapshot.devices {
        let asset_id = format!("{source}:{}", device.id);
        known_device_ids.insert(device.id.clone(), asset_id.clone());
        assets.insert(
            asset_id.clone(),
            NetworkAsset {
                asset_id,
                asset_type: canonical_asset_type(device.device_type.as_deref()),
                name: device.name,
                source: source.to_string(),
                confidence: Confidence::High,
                ip: device.ip.clone(),
                mac: device.mac,
                vendor: device.vendor,
                model: device.model,
                serial: device.serial,
                status: device.status,
                location: device.location,
                linked_host_key: match_host_key(hosts, device.ip.as_deref()),
                observations: device.observations,
            },
        );
    }

    for client in snapshot.clients {
        let asset_id = format!("{source}:client:{}", client.id);
        assets.insert(
            asset_id.clone(),
            NetworkAsset {
                asset_id: asset_id.clone(),
                asset_type: "wireless-client".to_string(),
                name: client.name,
                source: source.to_string(),
                confidence: Confidence::Medium,
                ip: client.ip.clone(),
                mac: client.mac.clone(),
                vendor: client.vendor,
                model: client.model,
                serial: None,
                status: client.status,
                location: client.ssid.clone(),
                linked_host_key: match_host_key(hosts, client.ip.as_deref()),
                observations: client.observations,
            },
        );
        if let Some(attached_device_id) = client.attached_device_id {
            let target_asset_id = known_device_ids
                .get(&attached_device_id)
                .cloned()
                .unwrap_or_else(|| format!("{source}:{attached_device_id}"));
            let edge = TopologyEdge {
                edge_id: format!("edge:{source}:client:{asset_id}:{target_asset_id}"),
                source_asset_id: asset_id.clone(),
                target_asset_id,
                relation: "client_of".to_string(),
                source: source.to_string(),
                confidence: Confidence::High,
                details: vec![
                    client
                        .ssid
                        .map(|ssid| format!("ssid={ssid}"))
                        .unwrap_or_else(|| "ssid=?".to_string()),
                    client
                        .vlan
                        .map(|vlan| format!("vlan={vlan}"))
                        .unwrap_or_else(|| "vlan=?".to_string()),
                ],
            };
            edges.insert(edge.edge_id.clone(), edge);
        }
    }

    for link in snapshot.links {
        let source_asset_id = known_device_ids
            .get(&link.source_id)
            .cloned()
            .unwrap_or_else(|| ensure_inferred_device(source, &link.source_id, assets));
        let target_asset_id = known_device_ids
            .get(&link.target_id)
            .cloned()
            .unwrap_or_else(|| ensure_inferred_device(source, &link.target_id, assets));
        let edge = TopologyEdge {
            edge_id: format!(
                "edge:{source}:{}:{}:{}",
                link.source_id, link.target_id, link.relation
            ),
            source_asset_id,
            target_asset_id,
            relation: link.relation,
            source: source.to_string(),
            confidence: link.confidence.unwrap_or(Confidence::Medium),
            details: vec![
                link.source_port
                    .map(|value| format!("local_port={value}"))
                    .unwrap_or_else(|| "local_port=?".to_string()),
                link.target_port
                    .map(|value| format!("remote_port={value}"))
                    .unwrap_or_else(|| "remote_port=?".to_string()),
                link.protocol
                    .map(|value| format!("protocol={value}"))
                    .unwrap_or_else(|| "protocol=?".to_string()),
            ],
        };
        edges.insert(edge.edge_id.clone(), edge);
    }

    for vlan in snapshot.vlans {
        if let Some(asset_id) = known_device_ids.get(&vlan.device_id).cloned() {
            if let Some(asset) = assets.get_mut(&asset_id) {
                asset.observations.push(format!(
                    "vlan={}{}",
                    vlan.vlan_id.unwrap_or_else(|| "?".to_string()),
                    vlan.name
                        .map(|name| format!(" ({name})"))
                        .unwrap_or_default()
                ));
            }
        }
    }

    for arp in snapshot.arp {
        let endpoint_key = canonical_endpoint_key(arp.mac.as_deref(), arp.ip.as_deref());
        let asset_id = format!("{source}:endpoint:{endpoint_key}");
        assets
            .entry(asset_id.clone())
            .or_insert_with(|| NetworkAsset {
                asset_id: asset_id.clone(),
                asset_type: "endpoint".to_string(),
                name: arp
                    .ip
                    .clone()
                    .or_else(|| arp.mac.clone())
                    .unwrap_or_else(|| "Neznámý endpoint".to_string()),
                source: source.to_string(),
                confidence: Confidence::Medium,
                ip: arp.ip.clone(),
                mac: arp.mac.clone(),
                vendor: None,
                model: None,
                serial: None,
                status: None,
                location: arp.vlan.clone(),
                linked_host_key: match_host_key(hosts, arp.ip.as_deref()),
                observations: vec![
                    arp.port
                        .clone()
                        .map(|port| format!("port={port}"))
                        .unwrap_or_else(|| "port=?".to_string()),
                    arp.vlan
                        .clone()
                        .map(|vlan| format!("vlan={vlan}"))
                        .unwrap_or_else(|| "vlan=?".to_string()),
                    "learned_via=arp".to_string(),
                ],
            });
        if let Some(source_asset_id) = known_device_ids.get(&arp.device_id).cloned() {
            let edge = TopologyEdge {
                edge_id: format!("edge:{source}:arp:{}:{}", arp.device_id, endpoint_key),
                source_asset_id,
                target_asset_id: asset_id,
                relation: "arp_seen".to_string(),
                source: source.to_string(),
                confidence: Confidence::Medium,
                details: vec![
                    arp.port
                        .map(|value| format!("port={value}"))
                        .unwrap_or_else(|| "port=?".to_string()),
                    arp.vlan
                        .map(|value| format!("vlan={value}"))
                        .unwrap_or_else(|| "vlan=?".to_string()),
                ],
            };
            edges.insert(edge.edge_id.clone(), edge);
        }
    }

    for fdb in snapshot.fdb {
        let endpoint_key = canonical_endpoint_key(fdb.mac.as_deref(), None);
        let asset_id = format!("{source}:endpoint:{endpoint_key}");
        assets
            .entry(asset_id.clone())
            .or_insert_with(|| NetworkAsset {
                asset_id: asset_id.clone(),
                asset_type: "endpoint".to_string(),
                name: fdb
                    .mac
                    .clone()
                    .unwrap_or_else(|| "FDB endpoint".to_string()),
                source: source.to_string(),
                confidence: Confidence::Low,
                ip: None,
                mac: fdb.mac.clone(),
                vendor: None,
                model: None,
                serial: None,
                status: None,
                location: fdb.vlan.clone(),
                linked_host_key: None,
                observations: vec![
                    fdb.port
                        .clone()
                        .map(|port| format!("port={port}"))
                        .unwrap_or_else(|| "port=?".to_string()),
                    fdb.vlan
                        .clone()
                        .map(|vlan| format!("vlan={vlan}"))
                        .unwrap_or_else(|| "vlan=?".to_string()),
                    "learned_via=fdb".to_string(),
                ],
            });
        if let Some(source_asset_id) = known_device_ids.get(&fdb.device_id).cloned() {
            let edge = TopologyEdge {
                edge_id: format!("edge:{source}:fdb:{}:{}", fdb.device_id, endpoint_key),
                source_asset_id,
                target_asset_id: asset_id,
                relation: "mac_learned_on".to_string(),
                source: source.to_string(),
                confidence: Confidence::Low,
                details: vec![
                    fdb.port
                        .map(|value| format!("port={value}"))
                        .unwrap_or_else(|| "port=?".to_string()),
                    fdb.vlan
                        .map(|value| format!("vlan={value}"))
                        .unwrap_or_else(|| "vlan=?".to_string()),
                ],
            };
            edges.insert(edge.edge_id.clone(), edge);
        }
    }
}
fn fetch_librenms_snapshot(
    base_url: &str,
    api_key_env: &str,
) -> Result<NormalizedControllerSnapshot> {
    let api_key = env::var(api_key_env).map_err(|_| {
        BakulaError::Config(format!(
            "Promenna prostredi {api_key_env} s LibreNMS API tokenem neni nastavena."
        ))
    })?;
    let client = Client::builder().user_agent("bakula-program/0.1").build()?;
    let headers = vec![("X-Auth-Token", api_key)];

    let devices_value = fetch_json(
        &client,
        &format!("{}/api/v0/devices?type=all", base_url.trim_end_matches('/')),
        &headers,
    )?;
    let links_value = fetch_json(
        &client,
        &format!("{}/api/v0/resources/links", base_url.trim_end_matches('/')),
        &headers,
    )?;
    let vlans_value = fetch_json(
        &client,
        &format!("{}/api/v0/resources/vlans", base_url.trim_end_matches('/')),
        &headers,
    )?;
    let ports_value = fetch_json(
        &client,
        &format!("{}/api/v0/ports", base_url.trim_end_matches('/')),
        &headers,
    )?;
    let fdb_value = fetch_json(
        &client,
        &format!(
            "{}/api/v0/resources/fdb/detail",
            base_url.trim_end_matches('/')
        ),
        &headers,
    )?;

    let mut snapshot = NormalizedControllerSnapshot::default();
    snapshot.devices = parse_generic_devices(&devices_value, "LibreNMS");
    snapshot.links = parse_librenms_links(&links_value);
    snapshot.vlans = parse_librenms_vlans(&vlans_value);
    snapshot.fdb = parse_librenms_fdb(&fdb_value);
    snapshot.arp = parse_librenms_arp(base_url, &client, &headers, &ports_value)?;
    snapshot.devices =
        enrich_librenms_devices_with_port_observations(snapshot.devices, &ports_value);
    Ok(snapshot)
}

fn fetch_meraki_snapshot(
    network_id: &str,
    api_key_env: &str,
    timespan_seconds: u32,
) -> Result<MerakiSnapshot> {
    let api_key = env::var(api_key_env).map_err(|_| {
        BakulaError::Config(format!(
            "Promenna prostredi {api_key_env} s Meraki API klicem neni nastavena."
        ))
    })?;
    let client = Client::builder().user_agent("bakula-program/0.1").build()?;

    let devices: Vec<MerakiDevice> = client
        .get(format!(
            "https://api.meraki.com/api/v1/networks/{network_id}/devices"
        ))
        .header("X-Cisco-Meraki-API-Key", api_key.clone())
        .send()?
        .error_for_status()?
        .json()?;

    let clients: Vec<MerakiClient> = client
        .get(format!(
            "https://api.meraki.com/api/v1/networks/{network_id}/clients"
        ))
        .header("X-Cisco-Meraki-API-Key", api_key.clone())
        .query(&[
            ("timespan", timespan_seconds.to_string()),
            ("perPage", "1000".to_string()),
        ])
        .send()?
        .error_for_status()?
        .json()?;

    let mut lldp_cdp = HashMap::new();
    for device in &devices {
        let response = client
            .get(format!(
                "https://api.meraki.com/api/v1/devices/{}/lldpCdp",
                device.serial
            ))
            .header("X-Cisco-Meraki-API-Key", api_key.clone())
            .send()?
            .error_for_status()?;
        let payload: Value = response.json()?;
        let neighbors = payload
            .pointer("/ports")
            .and_then(Value::as_object)
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(|(port_name, entry)| {
                        let candidate = entry
                            .get("lldp")
                            .or_else(|| entry.get("cdp"))
                            .cloned()
                            .unwrap_or(Value::Null);
                        if candidate.is_null() {
                            return None;
                        }
                        Some(MerakiLldpNeighbor {
                            source_port: Some(port_name.clone()),
                            remote_device_name: candidate
                                .get("deviceId")
                                .and_then(Value::as_str)
                                .map(ToString::to_string)
                                .or_else(|| {
                                    candidate
                                        .get("device")
                                        .and_then(Value::as_str)
                                        .map(ToString::to_string)
                                }),
                            remote_device_serial: None,
                            remote_port: candidate
                                .get("portId")
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                            protocol: if entry.get("lldp").is_some() {
                                Some("lldp".to_string())
                            } else {
                                Some("cdp".to_string())
                            },
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        lldp_cdp.insert(device.serial.clone(), neighbors);
    }

    Ok(MerakiSnapshot {
        devices,
        clients,
        lldp_cdp,
    })
}

fn fetch_generic_controller_snapshot(
    source: &str,
    token_env: &str,
    devices_url: Option<&str>,
    clients_url: Option<&str>,
    links_url: Option<&str>,
) -> Result<NormalizedControllerSnapshot> {
    let token = env::var(token_env).map_err(|_| {
        BakulaError::Config(format!(
            "Promenna prostredi {token_env} pro connector {source} neni nastavena."
        ))
    })?;
    let client = Client::builder().user_agent("bakula-program/0.1").build()?;
    let headers = vec![
        ("Authorization", format!("Bearer {token}")),
        ("X-API-Key", token.clone()),
    ];

    let devices_value = if let Some(url) = devices_url {
        Some(fetch_json(&client, url, &headers)?)
    } else {
        None
    };
    let clients_value = if let Some(url) = clients_url {
        Some(fetch_json(&client, url, &headers)?)
    } else {
        None
    };
    let links_value = if let Some(url) = links_url {
        Some(fetch_json(&client, url, &headers)?)
    } else {
        None
    };

    Ok(NormalizedControllerSnapshot {
        devices: devices_value
            .as_ref()
            .map(|value| parse_generic_devices(value, source))
            .unwrap_or_default(),
        clients: clients_value
            .as_ref()
            .map(|value| parse_generic_clients(value))
            .unwrap_or_default(),
        links: links_value
            .as_ref()
            .map(parse_generic_links)
            .unwrap_or_default(),
        ..Default::default()
    })
}

fn fetch_aruba_snapshot(
    base_url: &str,
    token_env: &str,
    site_id: &str,
) -> Result<NormalizedControllerSnapshot> {
    let token = env::var(token_env).map_err(|_| {
        BakulaError::Config(format!(
            "Promenna prostredi {token_env} pro Aruba Central bearer token neni nastavena."
        ))
    })?;
    let client = Client::builder().user_agent("bakula-program/0.1").build()?;
    let headers = vec![("Authorization", format!("Bearer {token}"))];
    let base = base_url.trim_end_matches('/');

    let devices = fetch_json(
        &client,
        &format!("{base}/platform/device_inventory/v1/devices"),
        &headers,
    )?;
    let clients = fetch_json(
        &client,
        &format!("{base}/monitoring/v2/clients?site={site_id}&limit=1000"),
        &headers,
    )?;
    let links = fetch_json(
        &client,
        &format!("{base}/topology_external_api/{site_id}"),
        &headers,
    )?;

    Ok(NormalizedControllerSnapshot {
        devices: parse_generic_devices(&devices, "Aruba"),
        clients: parse_generic_clients(&clients),
        links: parse_generic_links(&links),
        ..Default::default()
    })
}

fn fetch_json(client: &Client, url: &str, headers: &[(&str, String)]) -> Result<Value> {
    let mut request = client.get(url);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = request.send()?.error_for_status()?;
    response.json().map_err(BakulaError::Http)
}

fn build_lane(
    source: &str,
    lane_type: &str,
    title: &str,
    snapshot: &NormalizedControllerSnapshot,
) -> MonitoringLane {
    MonitoringLane {
        lane_id: format!("lane:{lane_type}:{source}"),
        lane_type: lane_type.to_string(),
        source: source.to_string(),
        title: title.to_string(),
        status: if snapshot.devices.is_empty()
            && snapshot.clients.is_empty()
            && snapshot.links.is_empty()
            && snapshot.arp.is_empty()
            && snapshot.fdb.is_empty()
        {
            "missing".to_string()
        } else if snapshot.links.is_empty() && snapshot.arp.is_empty() && snapshot.fdb.is_empty() {
            "partial".to_string()
        } else {
            "ok".to_string()
        },
        summary: format!(
            "Zařízení {}, klienti {}, vazby {}, VLAN {}, ARP {}, FDB {}, alerty {}.",
            snapshot.devices.len(),
            snapshot.clients.len(),
            snapshot.links.len(),
            snapshot.vlans.len(),
            snapshot.arp.len(),
            snapshot.fdb.len(),
            snapshot.alerts.len()
        ),
        evidence: snapshot
            .alerts
            .iter()
            .take(5)
            .map(|alert| format!("alert={} ({:?})", alert.title, alert.severity))
            .collect(),
        recommended_tools: vec![
            "nmap".to_string(),
            "snmp".to_string(),
            "librenms".to_string(),
            "controller-api".to_string(),
        ],
    }
}

fn canonical_asset_type(value: Option<&str>) -> String {
    let value = value.unwrap_or_default().to_ascii_lowercase();
    match value.as_str() {
        "wireless" | "access-point" | "ap" => "access-point".to_string(),
        "switch" | "stack" => "switch".to_string(),
        "router" => "router".to_string(),
        "firewall" | "security appliance" | "appliance" => "firewall".to_string(),
        "camera" => "camera".to_string(),
        "wireless-client" | "client" => "wireless-client".to_string(),
        _ => "network-device".to_string(),
    }
}

fn ensure_inferred_device(
    source: &str,
    raw_id: &str,
    assets: &mut BTreeMap<String, NetworkAsset>,
) -> String {
    let asset_id = format!("{source}:inferred:{raw_id}");
    assets
        .entry(asset_id.clone())
        .or_insert_with(|| NetworkAsset {
            asset_id: asset_id.clone(),
            asset_type: "network-device".to_string(),
            name: raw_id.to_string(),
            source: source.to_string(),
            confidence: Confidence::Low,
            ip: None,
            mac: None,
            vendor: None,
            model: None,
            serial: None,
            status: None,
            location: None,
            linked_host_key: None,
            observations: vec!["Inferred from topology evidence.".to_string()],
        });
    asset_id
}

fn canonical_endpoint_key(mac: Option<&str>, ip: Option<&str>) -> String {
    if let Some(mac) = mac {
        return mac
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_lowercase();
    }
    ip.unwrap_or("unknown")
        .replace(['.', ':', '/'], "-")
        .to_ascii_lowercase()
}

fn match_host_key(hosts: &[HostReport], ip: Option<&str>) -> Option<String> {
    let ip = ip?;
    hosts
        .iter()
        .find(|host| host.ip == ip)
        .map(|host| host.host_key.clone())
}

fn extract_array<'a>(value: &'a Value, candidate_keys: &[&str]) -> Vec<&'a Value> {
    if let Some(array) = value.as_array() {
        return array.iter().collect();
    }
    for key in candidate_keys {
        if let Some(array) = value.get(*key).and_then(Value::as_array) {
            return array.iter().collect();
        }
    }
    if let Some(data) = value.get("data") {
        return extract_array(data, candidate_keys);
    }
    if let Some(list) = value.pointer("/result/data") {
        return extract_array(list, candidate_keys);
    }
    Vec::new()
}
fn parse_generic_devices(value: &Value, vendor_name: &str) -> Vec<NormalizedDevice> {
    extract_array(value, &["devices", "device", "results"])
        .into_iter()
        .map(|item| NormalizedDevice {
            id: string_field(item, &["id", "device_id", "serial", "mac", "uuid"])
                .unwrap_or_else(|| "unknown".to_string()),
            name: string_field(item, &["name", "hostname", "display_name", "device_name"])
                .or_else(|| string_field(item, &["serial", "mac"]))
                .unwrap_or_else(|| "Bez názvu".to_string()),
            ip: string_field(
                item,
                &["ip", "ip_address", "management_ip", "lan_ip", "fixed_ip"],
            ),
            mac: string_field(item, &["mac", "mac_address"]),
            vendor: string_field(item, &["vendor", "manufacturer"])
                .or_else(|| Some(vendor_name.to_string())),
            model: string_field(item, &["model", "hardware", "platform"]),
            serial: string_field(item, &["serial", "serial_number"]),
            status: string_field(item, &["status", "state"]),
            location: string_field(item, &["location", "address", "site"]),
            device_type: string_field(item, &["type", "device_type", "product_type", "role"]),
            observations: collect_simple_observations(item, &["os", "version", "site", "role"]),
        })
        .collect()
}

fn parse_generic_clients(value: &Value) -> Vec<NormalizedClient> {
    extract_array(value, &["clients", "client", "results"])
        .into_iter()
        .map(|item| NormalizedClient {
            id: string_field(item, &["id", "client_id", "mac", "ip", "name"])
                .unwrap_or_else(|| "unknown".to_string()),
            name: string_field(item, &["name", "hostname", "description", "display_name"])
                .or_else(|| string_field(item, &["mac", "ip"]))
                .unwrap_or_else(|| "Bez názvu".to_string()),
            ip: string_field(item, &["ip", "ip_address", "fixed_ip"]),
            mac: string_field(item, &["mac", "mac_address"]),
            vendor: string_field(item, &["vendor", "manufacturer", "oui"]),
            model: string_field(item, &["model", "os", "platform"]),
            status: string_field(item, &["status", "state"]),
            ssid: string_field(item, &["ssid", "network_name"]),
            vlan: string_field(item, &["vlan", "vlan_id"]),
            attached_device_id: string_field(
                item,
                &[
                    "recent_device_serial",
                    "device_id",
                    "ap_id",
                    "connected_device_id",
                    "radio_mac",
                ],
            ),
            observations: collect_simple_observations(item, &["radio", "channel", "signal"]),
        })
        .collect()
}

fn parse_generic_links(value: &Value) -> Vec<NormalizedLink> {
    if let Some(edges) = value.get("edges") {
        return parse_generic_links(edges);
    }
    extract_array(value, &["links", "topology", "results"])
        .into_iter()
        .filter_map(|item| {
            let source_id =
                string_field(item, &["source_id", "source", "from", "local_device_id"])?;
            let target_id = string_field(item, &["target_id", "target", "to", "remote_device_id"])?;
            Some(NormalizedLink {
                source_id,
                target_id,
                relation: string_field(item, &["relation", "protocol", "type"])
                    .unwrap_or_else(|| "linked".to_string()),
                source_port: string_field(item, &["source_port", "local_port", "port_a"]),
                target_port: string_field(item, &["target_port", "remote_port", "port_b"]),
                protocol: string_field(item, &["protocol"]),
                confidence: Some(match string_field(item, &["confidence"]).as_deref() {
                    Some("high") => Confidence::High,
                    Some("low") => Confidence::Low,
                    _ => Confidence::Medium,
                }),
            })
        })
        .collect()
}

fn parse_librenms_links(value: &Value) -> Vec<NormalizedLink> {
    extract_array(value, &["links"])
        .into_iter()
        .filter_map(|item| {
            Some(NormalizedLink {
                source_id: string_field(item, &["local_device_id"])?,
                target_id: string_field(item, &["remote_device_id", "remote_hostname"])
                    .or_else(|| string_field(item, &["remote_port"]))?,
                relation: string_field(item, &["protocol"]).unwrap_or_else(|| "lldp".to_string()),
                source_port: string_field(item, &["local_port_id", "local_port"]),
                target_port: string_field(item, &["remote_port"]),
                protocol: string_field(item, &["protocol"]),
                confidence: Some(Confidence::Medium),
            })
        })
        .collect()
}

fn parse_librenms_vlans(value: &Value) -> Vec<NormalizedVlan> {
    extract_array(value, &["vlans"])
        .into_iter()
        .map(|item| NormalizedVlan {
            device_id: string_field(item, &["device_id"]).unwrap_or_else(|| "unknown".to_string()),
            vlan_id: string_field(item, &["vlan_vlan", "vlan_id"]),
            name: string_field(item, &["vlan_name", "name"]),
            port: string_field(item, &["port_id", "ifName"]),
        })
        .collect()
}

fn parse_librenms_fdb(value: &Value) -> Vec<NormalizedFdb> {
    extract_array(value, &["ports_fdb", "fdb"])
        .into_iter()
        .map(|item| NormalizedFdb {
            device_id: string_field(item, &["device_id"]).unwrap_or_else(|| "unknown".to_string()),
            mac: string_field(item, &["mac_address", "mac"]),
            port: string_field(item, &["ifName", "port_id", "ifDescr"]),
            vlan: string_field(item, &["vlan_id", "vlan"]),
        })
        .collect()
}

fn parse_librenms_arp(
    base_url: &str,
    client: &Client,
    headers: &[(&str, String)],
    ports_value: &Value,
) -> Result<Vec<NormalizedArp>> {
    let mut device_ids = extract_array(ports_value, &["ports"])
        .into_iter()
        .filter_map(|item| string_field(item, &["device_id"]))
        .collect::<Vec<_>>();
    device_ids.sort();
    device_ids.dedup();
    let mut arp = Vec::new();
    for device_id in device_ids {
        let url = format!(
            "{}/api/v0/resources/ip/arp/{}",
            base_url.trim_end_matches('/'),
            device_id
        );
        let value = match fetch_json(client, &url, headers) {
            Ok(value) => value,
            Err(_) => continue,
        };
        arp.extend(
            extract_array(&value, &["ip", "arp"])
                .into_iter()
                .map(|item| NormalizedArp {
                    device_id: device_id.clone(),
                    ip: string_field(item, &["ipv4_address", "ip"]),
                    mac: string_field(item, &["mac_address", "mac"]),
                    port: string_field(item, &["ifName", "port_id", "ifDescr"]),
                    vlan: string_field(item, &["vlan_id", "vlan"]),
                }),
        );
    }
    Ok(arp)
}

fn enrich_librenms_devices_with_port_observations(
    mut devices: Vec<NormalizedDevice>,
    ports_value: &Value,
) -> Vec<NormalizedDevice> {
    let mut port_counts = HashMap::<String, usize>::new();
    for item in extract_array(ports_value, &["ports"]) {
        if let Some(device_id) = string_field(item, &["device_id"]) {
            *port_counts.entry(device_id).or_default() += 1;
        }
    }
    for device in &mut devices {
        if let Some(count) = port_counts.get(&device.id) {
            device.observations.push(format!("ports_total={count}"));
        }
    }
    devices
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key) {
            if let Some(text) = found.as_str() {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
            if let Some(number) = found.as_i64() {
                return Some(number.to_string());
            }
            if let Some(number) = found.as_u64() {
                return Some(number.to_string());
            }
        }
    }
    None
}

fn collect_simple_observations(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| string_field(value, &[*key]).map(|found| format!("{key}={found}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::model::HostReport;

    use super::{
        ContextConfig, NormalizedControllerSnapshot, SnmpTopologySnapshot, collect_context,
    };

    #[test]
    fn parses_snapshots_without_hosts() {
        let snmp: SnmpTopologySnapshot = serde_json::from_str(
            r#"{
                "devices":[{"id":"sw1","name":"CoreSwitch","ip":"192.168.1.2","device_type":"switch"}],
                "neighbors":[{"local_device_id":"sw1","remote_name":"AP-01","remote_ip":"192.168.1.10","local_port":"Gi1/0/1","remote_port":"eth0","protocol":"lldp"}],
                "arp":[{"device_id":"sw1","ip":"192.168.1.55","mac":"aa:bb:cc:dd:ee:ff","port":"Gi1/0/10","vlan":"20"}]
            }"#,
        )
        .expect("snmp json");
        assert_eq!(snmp.devices.len(), 1);
        assert_eq!(snmp.neighbors.len(), 1);

        let generic: NormalizedControllerSnapshot = serde_json::from_str(
            r#"{
                "devices":[{"id":"ap-01","name":"AP-01","ip":"192.168.1.10","device_type":"access-point"}],
                "clients":[{"id":"c1","name":"Notebook","ip":"192.168.1.55","attached_device_id":"ap-01","ssid":"Office"}],
                "links":[{"source_id":"ap-01","target_id":"sw1","relation":"uplink"}]
            }"#,
        )
        .expect("generic json");
        assert_eq!(generic.devices.len(), 1);
        assert_eq!(generic.clients.len(), 1);

        let bundle = collect_context(
            &Vec::<HostReport>::new(),
            &ContextConfig {
                snmp_snapshot: None,
                librenms_snapshot: None,
                librenms_base_url: None,
                librenms_token_env: "LIBRENMS_TOKEN".to_string(),
                meraki_snapshot: None,
                meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
                meraki_network_id: None,
                meraki_timespan_seconds: 3600,
                unifi_snapshot: None,
                unifi_devices_url: None,
                unifi_clients_url: None,
                unifi_links_url: None,
                unifi_api_key_env: "UNIFI_API_KEY".to_string(),
                aruba_snapshot: None,
                aruba_base_url: None,
                aruba_token_env: "ARUBA_TOKEN".to_string(),
                aruba_site_id: None,
                omada_snapshot: None,
                omada_devices_url: None,
                omada_clients_url: None,
                omada_links_url: None,
                omada_access_token_env: "OMADA_TOKEN".to_string(),
            },
        )
        .expect("empty context");
        assert!(bundle.network_assets.is_empty());
    }
}
