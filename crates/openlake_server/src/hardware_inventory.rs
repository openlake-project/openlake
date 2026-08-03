use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct HardwareSnapshot {
    pub schema_version: &'static str,
    pub collected_at_unix_ms: u128,
    pub collection_status: String,
    pub system: SystemInventory,
    pub cpu: CpuInventory,
    pub memory: MemoryInventory,
    pub numa_nodes: Vec<NumaNode>,
    pub pci_devices: Vec<PciDevice>,
    pub gpus: Vec<GpuDevice>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub infiniband_devices: Vec<InfiniBandDevice>,
    pub disks: Vec<DiskDevice>,
    pub openlake: OpenLakeAllocation,
    pub subsystems: Vec<SubsystemStatus>,
}

#[derive(Clone, Default, Serialize)]
pub(crate) struct SystemInventory {
    pub operating_system: String,
    pub architecture: String,
    pub kernel_release: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub board_vendor: Option<String>,
    pub board_name: Option<String>,
}

#[derive(Clone, Default, Serialize)]
pub(crate) struct CpuInventory {
    pub architecture: String,
    pub model: Option<String>,
    pub logical_cpu_count: usize,
    pub physical_core_count: Option<usize>,
    pub package_count: Option<usize>,
    pub packages: Vec<CpuPackage>,
}

#[derive(Clone, Serialize)]
pub(crate) struct CpuPackage {
    pub id: i32,
    pub cores: Vec<CpuCore>,
}

#[derive(Clone, Serialize)]
pub(crate) struct CpuCore {
    pub id: i32,
    pub logical_cpus: Vec<u32>,
}

#[derive(Clone, Default, Serialize)]
pub(crate) struct MemoryInventory {
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
}

#[derive(Clone, Serialize)]
pub(crate) struct NumaNode {
    pub id: u32,
    pub logical_cpus: Vec<u32>,
    pub memory_total_bytes: Option<u64>,
    pub pci_devices: Vec<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct PciDevice {
    pub address: String,
    pub vendor_id: Option<String>,
    pub vendor_name: Option<String>,
    pub device_id: Option<String>,
    pub subsystem_vendor_id: Option<String>,
    pub subsystem_device_id: Option<String>,
    pub class_id: Option<String>,
    pub device_type: String,
    pub driver: Option<String>,
    pub numa_node: Option<i32>,
    pub parent_address: Option<String>,
    pub current_link_speed: Option<String>,
    pub current_link_width: Option<u64>,
    pub max_link_speed: Option<String>,
    pub max_link_width: Option<u64>,
}

#[derive(Clone, Serialize)]
pub(crate) struct GpuDevice {
    pub index: Option<u32>,
    pub name: String,
    pub vendor: String,
    pub uuid: Option<String>,
    pub pci_address: Option<String>,
    pub numa_node: Option<i32>,
    pub memory_total_bytes: Option<u64>,
    pub nvlinks: Vec<NvLink>,
    pub source: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct NvLink {
    pub link: u32,
    pub state: String,
    pub bandwidth_gbps: Option<f64>,
    pub peer_pci_address: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct NetworkInterface {
    pub name: String,
    pub mac_address: Option<String>,
    pub operational_state: Option<String>,
    pub mtu: Option<u64>,
    pub speed_mbps: Option<u64>,
    pub duplex: Option<String>,
    pub pci_address: Option<String>,
    pub numa_node: Option<i32>,
    pub driver: Option<String>,
    pub infiniband_device: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct InfiniBandDevice {
    pub name: String,
    pub firmware_version: Option<String>,
    pub node_guid: Option<String>,
    pub pci_address: Option<String>,
    pub numa_node: Option<i32>,
    pub ports: Vec<InfiniBandPort>,
}

#[derive(Clone, Serialize)]
pub(crate) struct InfiniBandPort {
    pub port: u32,
    pub state: Option<String>,
    pub physical_state: Option<String>,
    pub rate: Option<String>,
    pub link_layer: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct DiskDevice {
    pub name: String,
    pub device_path: String,
    pub major_minor: Option<String>,
    pub size_bytes: Option<u64>,
    pub rotational: Option<bool>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub transport: Option<String>,
    pub pci_address: Option<String>,
    pub numa_node: Option<i32>,
}

#[derive(Clone, Serialize)]
pub(crate) struct OpenLakeAllocation {
    pub kv_cache_capacity_bytes: Option<u64>,
    pub data_paths: Vec<DataPathAllocation>,
}

#[derive(Clone, Serialize)]
pub(crate) struct DataPathAllocation {
    pub path: String,
    pub mount_point: Option<String>,
    pub filesystem: Option<String>,
    pub source: Option<String>,
    pub device: Option<String>,
    pub disk: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct SubsystemStatus {
    pub subsystem: &'static str,
    pub status: &'static str,
    pub detail: Option<String>,
}

pub(crate) fn collect(
    data_paths: &[PathBuf],
    kv_cache_capacity_bytes: Option<u64>,
) -> HardwareSnapshot {
    #[cfg(target_os = "linux")]
    {
        collect_linux(data_paths, kv_cache_capacity_bytes)
    }
    #[cfg(target_os = "macos")]
    {
        collect_macos(data_paths, kv_cache_capacity_bytes)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        collect_portable(data_paths, kv_cache_capacity_bytes)
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(target_os = "linux")]
fn parse_u64(value: Option<String>) -> Option<u64> {
    value?.trim().parse().ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn basic_system(operating_system: &str) -> SystemInventory {
    SystemInventory {
        operating_system: operating_system.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        ..SystemInventory::default()
    }
}

#[cfg(target_os = "linux")]
fn collect_linux(data_paths: &[PathBuf], kv_cache_capacity_bytes: Option<u64>) -> HardwareSnapshot {
    let system = linux_system_inventory();
    let cpu = linux_cpu_inventory();
    let memory = linux_memory_inventory();
    let pci_devices = linux_pci_devices();
    let numa_nodes = linux_numa_nodes(&pci_devices);
    let (gpus, gpu_detail) = linux_gpus(&pci_devices);
    let network_interfaces = linux_network_interfaces();
    let infiniband_devices = linux_infiniband_devices();
    let disks = linux_disks();
    let openlake = OpenLakeAllocation {
        kv_cache_capacity_bytes,
        data_paths: linux_data_path_allocations(data_paths, &disks),
    };
    let mut subsystems = vec![
        status("system", present(!system.architecture.is_empty()), None),
        status("cpu", present(cpu.logical_cpu_count > 0), None),
        status("memory", present(memory.total_bytes.is_some()), None),
        status("numa", absent_or_available(!numa_nodes.is_empty()), None),
        status("pci", absent_or_available(!pci_devices.is_empty()), None),
        status("gpu", absent_or_available(!gpus.is_empty()), gpu_detail),
        status("network", present(!network_interfaces.is_empty()), None),
        status(
            "infiniband",
            absent_or_available(!infiniband_devices.is_empty()),
            None,
        ),
        status("disk", present(!disks.is_empty()), None),
    ];
    subsystems.push(status("openlake_mapping", "available", None));
    let collection_status = overall_status(&subsystems);
    HardwareSnapshot {
        schema_version: "1.0",
        collected_at_unix_ms: now_unix_ms(),
        collection_status,
        system,
        cpu,
        memory,
        numa_nodes,
        pci_devices,
        gpus,
        network_interfaces,
        infiniband_devices,
        disks,
        openlake,
        subsystems,
    }
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let value = std::fs::read_to_string(path).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(target_os = "linux")]
fn linux_system_inventory() -> SystemInventory {
    SystemInventory {
        operating_system: "linux".into(),
        architecture: std::env::consts::ARCH.into(),
        kernel_release: read_trimmed("/proc/sys/kernel/osrelease"),
        hostname: read_trimmed("/proc/sys/kernel/hostname"),
        vendor: read_trimmed("/sys/class/dmi/id/sys_vendor"),
        product_name: read_trimmed("/sys/class/dmi/id/product_name"),
        product_version: read_trimmed("/sys/class/dmi/id/product_version"),
        board_vendor: read_trimmed("/sys/class/dmi/id/board_vendor"),
        board_name: read_trimmed("/sys/class/dmi/id/board_name"),
    }
}

#[cfg(target_os = "linux")]
fn linux_cpu_inventory() -> CpuInventory {
    use std::collections::BTreeMap;

    let model = read_trimmed("/proc/cpuinfo").and_then(|text| {
        text.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            matches!(key.trim(), "model name" | "Hardware" | "Processor")
                .then(|| value.trim().to_owned())
        })
    });
    let mut topology: BTreeMap<i32, BTreeMap<i32, Vec<u32>>> = BTreeMap::new();
    let mut logical_cpu_count = 0;
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(cpu_id) = name
                .to_str()
                .and_then(|name| name.strip_prefix("cpu"))
                .and_then(|id| id.parse::<u32>().ok())
            else {
                continue;
            };
            logical_cpu_count += 1;
            let package = read_trimmed(entry.path().join("topology/physical_package_id"))
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let core = read_trimmed(entry.path().join("topology/core_id"))
                .and_then(|value| value.parse().ok())
                .unwrap_or(cpu_id as i32);
            topology
                .entry(package)
                .or_default()
                .entry(core)
                .or_default()
                .push(cpu_id);
        }
    }
    let packages = topology
        .into_iter()
        .map(|(id, cores)| CpuPackage {
            id,
            cores: cores
                .into_iter()
                .map(|(id, mut logical_cpus)| {
                    logical_cpus.sort_unstable();
                    CpuCore { id, logical_cpus }
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let physical_core_count = packages.iter().map(|package| package.cores.len()).sum();
    CpuInventory {
        architecture: std::env::consts::ARCH.into(),
        model,
        logical_cpu_count,
        physical_core_count: Some(physical_core_count),
        package_count: Some(packages.len()),
        packages,
    }
}

#[cfg(target_os = "linux")]
fn linux_memory_inventory() -> MemoryInventory {
    let text = read_trimmed("/proc/meminfo").unwrap_or_default();
    MemoryInventory {
        total_bytes: meminfo_bytes(&text, "MemTotal"),
        available_bytes: meminfo_bytes(&text, "MemAvailable"),
    }
}

#[cfg(any(target_os = "linux", test))]
fn meminfo_bytes(text: &str, field: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.split_whitespace().last() != Some(field) {
            return None;
        }
        value
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
            .and_then(|kb| kb.checked_mul(1024))
    })
}

#[cfg(target_os = "linux")]
fn linux_numa_nodes(pci_devices: &[PciDevice]) -> Vec<NumaNode> {
    let mut nodes = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") else {
        return nodes;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix("node"))
            .and_then(|id| id.parse::<u32>().ok())
        else {
            continue;
        };
        let logical_cpus = read_trimmed(entry.path().join("cpulist"))
            .map(|value| parse_cpu_list(&value))
            .unwrap_or_default();
        let memory_total_bytes = read_trimmed(entry.path().join("meminfo"))
            .and_then(|text| meminfo_bytes(&text, "MemTotal"));
        let pci_devices = pci_devices
            .iter()
            .filter(|device| device.numa_node == Some(id as i32))
            .map(|device| device.address.clone())
            .collect();
        nodes.push(NumaNode {
            id,
            logical_cpus,
            memory_total_bytes,
            pci_devices,
        });
    }
    nodes.sort_by_key(|node| node.id);
    nodes
}

#[cfg(any(target_os = "linux", test))]
fn parse_cpu_list(value: &str) -> Vec<u32> {
    let mut cpus = Vec::new();
    for segment in value
        .trim()
        .split(',')
        .filter(|segment| !segment.is_empty())
    {
        if let Some((start, end)) = segment.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.parse::<u32>(), end.parse::<u32>()) {
                cpus.extend(start..=end);
            }
        } else if let Ok(cpu) = segment.parse() {
            cpus.push(cpu);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

#[cfg(target_os = "linux")]
fn linux_pci_devices() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return devices;
    };
    for entry in entries.flatten() {
        let address = entry.file_name().to_string_lossy().into_owned();
        let vendor_id = read_trimmed(entry.path().join("vendor")).map(strip_hex_prefix);
        let class_id = read_trimmed(entry.path().join("class")).map(strip_hex_prefix);
        let driver = std::fs::read_link(entry.path().join("driver"))
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            });
        let numa_node = read_trimmed(entry.path().join("numa_node"))
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value >= 0);
        let parent_address = std::fs::canonicalize(entry.path())
            .ok()
            .and_then(|path| parent_pci_address(&path, &address));
        devices.push(PciDevice {
            address,
            vendor_name: pci_vendor_display_name(vendor_id.as_deref()).map(str::to_owned),
            vendor_id,
            device_id: read_trimmed(entry.path().join("device")).map(strip_hex_prefix),
            subsystem_vendor_id: read_trimmed(entry.path().join("subsystem_vendor"))
                .map(strip_hex_prefix),
            subsystem_device_id: read_trimmed(entry.path().join("subsystem_device"))
                .map(strip_hex_prefix),
            device_type: pci_device_type(class_id.as_deref()),
            class_id,
            driver,
            numa_node,
            parent_address,
            current_link_speed: read_trimmed(entry.path().join("current_link_speed")),
            current_link_width: parse_u64(read_trimmed(entry.path().join("current_link_width"))),
            max_link_speed: read_trimmed(entry.path().join("max_link_speed")),
            max_link_width: parse_u64(read_trimmed(entry.path().join("max_link_width"))),
        });
    }
    devices.sort_by(|left, right| left.address.cmp(&right.address));
    devices
}

#[cfg(target_os = "linux")]
fn strip_hex_prefix(value: String) -> String {
    value
        .strip_prefix("0x")
        .unwrap_or(&value)
        .to_ascii_lowercase()
}

#[cfg(target_os = "linux")]
fn pci_device_type(class_id: Option<&str>) -> String {
    match class_id.unwrap_or_default().get(0..2) {
        Some("01") => "storage_controller",
        Some("02") => "network_controller",
        Some("03") => "display_controller",
        Some("06") => "bridge",
        Some("0c") => "serial_bus_controller",
        Some("12") => "processing_accelerator",
        _ => "other",
    }
    .into()
}

#[cfg(target_os = "linux")]
fn parent_pci_address(path: &Path, address: &str) -> Option<String> {
    path.components()
        .rev()
        .filter_map(|component| component.as_os_str().to_str())
        .skip_while(|component| *component == address)
        .find(|component| is_pci_address(component))
        .map(str::to_owned)
}

#[cfg(any(target_os = "linux", test))]
fn is_pci_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10) || byte.is_ascii_hexdigit())
}

#[cfg(target_os = "linux")]
fn pci_address_from_path(path: &Path) -> Option<String> {
    path.components()
        .rev()
        .filter_map(|component| component.as_os_str().to_str())
        .find(|component| is_pci_address(component))
        .map(str::to_owned)
}

#[cfg(target_os = "linux")]
fn linux_gpus(pci_devices: &[PciDevice]) -> (Vec<GpuDevice>, Option<String>) {
    let mut gpus = pci_devices
        .iter()
        .filter(|device| {
            device.device_type == "display_controller"
                || device.device_type == "processing_accelerator"
        })
        .map(|device| GpuDevice {
            index: None,
            name: format!(
                "PCI {}:{}",
                device.vendor_id.as_deref().unwrap_or("unknown"),
                device.device_id.as_deref().unwrap_or("unknown")
            ),
            vendor: pci_vendor_name(device.vendor_id.as_deref()).into(),
            uuid: None,
            pci_address: Some(device.address.clone()),
            numa_node: device.numa_node,
            memory_total_bytes: None,
            nvlinks: Vec::new(),
            source: "sysfs".into(),
        })
        .collect::<Vec<_>>();

    let Some(output) = command_output(
        "nvidia-smi",
        &[
            "--query-gpu=index,uuid,name,pci.bus_id,memory.total",
            "--format=csv,noheader,nounits",
        ],
    ) else {
        let detail = gpus
            .iter()
            .any(|gpu| gpu.vendor.eq_ignore_ascii_case("NVIDIA"))
            .then(|| {
                "NVIDIA device identity is available through sysfs; NVML is unavailable".into()
            });
        return (gpus, detail);
    };

    for line in output.lines() {
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() < 5 {
            continue;
        }
        let index = fields[0].parse::<u32>().ok();
        let pci_address = normalize_pci_address(fields[3]);
        let memory_total_bytes = fields[4]
            .parse::<u64>()
            .ok()
            .and_then(|mib| mib.checked_mul(1024 * 1024));
        let nvlinks = index.map(linux_nvlinks).unwrap_or_default();
        if let Some(gpu) = gpus.iter_mut().find(|gpu| {
            gpu.pci_address
                .as_deref()
                .map(normalize_pci_address)
                .as_deref()
                == Some(pci_address.as_str())
        }) {
            gpu.index = index;
            gpu.uuid = Some(fields[1].to_owned());
            gpu.name = fields[2].to_owned();
            gpu.vendor = "NVIDIA".into();
            gpu.memory_total_bytes = memory_total_bytes;
            gpu.nvlinks = nvlinks;
            gpu.source = "NVML (nvidia-smi)".into();
        } else {
            gpus.push(GpuDevice {
                index,
                name: fields[2].to_owned(),
                vendor: "NVIDIA".into(),
                uuid: Some(fields[1].to_owned()),
                pci_address: Some(pci_address.clone()),
                numa_node: pci_devices
                    .iter()
                    .find(|device| normalize_pci_address(&device.address) == pci_address)
                    .and_then(|device| device.numa_node),
                memory_total_bytes,
                nvlinks,
                source: "NVML (nvidia-smi)".into(),
            });
        }
    }
    gpus.sort_by_key(|gpu| gpu.index.unwrap_or(u32::MAX));
    (gpus, None)
}

#[cfg(target_os = "linux")]
fn normalize_pci_address(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    if value.len() > 12 {
        value[value.len() - 12..].to_owned()
    } else {
        value
    }
}

#[cfg(target_os = "linux")]
fn linux_nvlinks(index: u32) -> Vec<NvLink> {
    let index = index.to_string();
    let Some(output) = command_output("nvidia-smi", &["nvlink", "--status", "-i", &index]) else {
        return Vec::new();
    };
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("Link ")?;
            let (link, state) = rest.split_once(':')?;
            let link = link.trim().parse().ok()?;
            let state = state.trim().to_owned();
            let bandwidth_gbps = state
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .filter(|_| state.contains("GB/s"));
            Some(NvLink {
                link,
                state,
                bandwidth_gbps,
                peer_pci_address: None,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn pci_vendor_name(vendor_id: Option<&str>) -> &'static str {
    pci_vendor_display_name(vendor_id).unwrap_or("Unknown")
}

#[cfg(any(target_os = "linux", test))]
fn pci_vendor_display_name(vendor_id: Option<&str>) -> Option<&'static str> {
    match vendor_id.unwrap_or_default().to_ascii_lowercase().as_str() {
        "10de" => Some("NVIDIA"),
        "1002" | "1022" => Some("AMD"),
        "8086" => Some("Intel"),
        "15b3" => Some("NVIDIA Networking"),
        "14e4" => Some("Broadcom"),
        "1d0f" => Some("Amazon"),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn linux_network_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return interfaces;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let device_path = std::fs::canonicalize(entry.path().join("device")).ok();
        let pci_address = device_path.as_deref().and_then(pci_address_from_path);
        let numa_node = pci_address
            .as_deref()
            .and_then(|address| {
                read_trimmed(
                    Path::new("/sys/bus/pci/devices")
                        .join(address)
                        .join("numa_node"),
                )
            })
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value >= 0);
        let driver = device_path.as_ref().and_then(|path| {
            std::fs::read_link(path.join("driver"))
                .ok()
                .and_then(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
        });
        interfaces.push(NetworkInterface {
            name: name.clone(),
            mac_address: read_trimmed(entry.path().join("address")),
            operational_state: read_trimmed(entry.path().join("operstate")),
            mtu: parse_u64(read_trimmed(entry.path().join("mtu"))),
            speed_mbps: parse_u64(read_trimmed(entry.path().join("speed"))),
            duplex: read_trimmed(entry.path().join("duplex")),
            pci_address,
            numa_node,
            driver,
            infiniband_device: infiniband_for_interface(&name),
        });
    }
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    interfaces
}

#[cfg(target_os = "linux")]
fn infiniband_for_interface(interface: &str) -> Option<String> {
    let entries = std::fs::read_dir("/sys/class/infiniband").ok()?;
    for entry in entries.flatten() {
        if entry.path().join("device/net").join(interface).exists() {
            return Some(entry.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn linux_infiniband_devices() -> Vec<InfiniBandDevice> {
    let mut devices = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/infiniband") else {
        return devices;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let pci_address = std::fs::canonicalize(path.join("device"))
            .ok()
            .as_deref()
            .and_then(pci_address_from_path);
        let numa_node = pci_address
            .as_deref()
            .and_then(|address| {
                read_trimmed(
                    Path::new("/sys/bus/pci/devices")
                        .join(address)
                        .join("numa_node"),
                )
            })
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value >= 0);
        let mut ports = Vec::new();
        if let Ok(port_entries) = std::fs::read_dir(path.join("ports")) {
            for port_entry in port_entries.flatten() {
                let Some(port) = port_entry
                    .file_name()
                    .to_str()
                    .and_then(|port| port.parse().ok())
                else {
                    continue;
                };
                ports.push(InfiniBandPort {
                    port,
                    state: read_trimmed(port_entry.path().join("state")),
                    physical_state: read_trimmed(port_entry.path().join("phys_state")),
                    rate: read_trimmed(port_entry.path().join("rate")),
                    link_layer: read_trimmed(port_entry.path().join("link_layer")),
                });
            }
        }
        ports.sort_by_key(|port| port.port);
        devices.push(InfiniBandDevice {
            name: entry.file_name().to_string_lossy().into_owned(),
            firmware_version: read_trimmed(path.join("fw_ver")),
            node_guid: read_trimmed(path.join("node_guid")),
            pci_address,
            numa_node,
            ports,
        });
    }
    devices.sort_by(|left, right| left.name.cmp(&right.name));
    devices
}

#[cfg(target_os = "linux")]
fn linux_disks() -> Vec<DiskDevice> {
    let mut disks = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/block") else {
        return disks;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.join("partition").exists()
            || name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("zram")
        {
            continue;
        }
        let pci_address = std::fs::canonicalize(path.join("device"))
            .ok()
            .as_deref()
            .and_then(pci_address_from_path);
        let numa_node = pci_address
            .as_deref()
            .and_then(|address| {
                read_trimmed(
                    Path::new("/sys/bus/pci/devices")
                        .join(address)
                        .join("numa_node"),
                )
            })
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value >= 0);
        disks.push(DiskDevice {
            name: name.clone(),
            device_path: format!("/dev/{name}"),
            major_minor: read_trimmed(path.join("dev")),
            size_bytes: parse_u64(read_trimmed(path.join("size")))
                .and_then(|sectors| sectors.checked_mul(512)),
            rotational: parse_u64(read_trimmed(path.join("queue/rotational")))
                .map(|value| value != 0),
            vendor: read_trimmed(path.join("device/vendor")),
            model: read_trimmed(path.join("device/model")),
            transport: read_trimmed(path.join("device/transport")),
            pci_address,
            numa_node,
        });
    }
    disks.sort_by(|left, right| left.name.cmp(&right.name));
    disks
}

#[cfg(target_os = "linux")]
struct MountRecord {
    device: String,
    mount_point: PathBuf,
    filesystem: String,
    source: String,
}

#[cfg(target_os = "linux")]
fn linux_data_path_allocations(
    data_paths: &[PathBuf],
    disks: &[DiskDevice],
) -> Vec<DataPathAllocation> {
    let mounts = read_mountinfo();
    data_paths
        .iter()
        .map(|data_path| {
            let resolved = std::fs::canonicalize(data_path).unwrap_or_else(|_| data_path.clone());
            let mount = mounts
                .iter()
                .filter(|mount| resolved.starts_with(&mount.mount_point))
                .max_by_key(|mount| mount.mount_point.components().count());
            let disk = mount.and_then(|mount| disk_for_device(&mount.device, disks));
            DataPathAllocation {
                path: data_path.to_string_lossy().into_owned(),
                mount_point: mount.map(|mount| mount.mount_point.to_string_lossy().into_owned()),
                filesystem: mount.map(|mount| mount.filesystem.clone()),
                source: mount.map(|mount| mount.source.clone()),
                device: mount.map(|mount| mount.device.clone()),
                disk,
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn read_mountinfo() -> Vec<MountRecord> {
    let Some(text) = read_trimmed("/proc/self/mountinfo") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            let fields = before.split_whitespace().collect::<Vec<_>>();
            let after = after.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 5 || after.len() < 2 {
                return None;
            }
            Some(MountRecord {
                device: fields[2].to_owned(),
                mount_point: PathBuf::from(unescape_mount(fields[4])),
                filesystem: after[0].to_owned(),
                source: unescape_mount(after[1]),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(target_os = "linux")]
fn disk_for_device(device: &str, disks: &[DiskDevice]) -> Option<String> {
    let canonical = std::fs::canonicalize(Path::new("/sys/dev/block").join(device)).ok()?;
    canonical
        .components()
        .rev()
        .filter_map(|component| component.as_os_str().to_str())
        .find(|component| disks.iter().any(|disk| disk.name == *component))
        .map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn collect_macos(data_paths: &[PathBuf], kv_cache_capacity_bytes: Option<u64>) -> HardwareSnapshot {
    let logical_cpu_count = command_output("/usr/sbin/sysctl", &["-n", "hw.logicalcpu"])
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let physical_core_count = command_output("/usr/sbin/sysctl", &["-n", "hw.physicalcpu"])
        .and_then(|value| value.parse().ok());
    let mut packages = Vec::new();
    if let Some(cores) = physical_core_count {
        packages.push(CpuPackage {
            id: 0,
            cores: (0..cores)
                .map(|id| CpuCore {
                    id: id as i32,
                    logical_cpus: Vec::new(),
                })
                .collect(),
        });
    }
    let system = SystemInventory {
        operating_system: "macos".into(),
        architecture: std::env::consts::ARCH.into(),
        kernel_release: command_output("/usr/sbin/sysctl", &["-n", "kern.osrelease"]),
        hostname: command_output("/bin/hostname", &[]),
        vendor: Some("Apple Inc.".into()),
        product_name: command_output("/usr/sbin/sysctl", &["-n", "hw.model"]),
        product_version: command_output("/usr/bin/sw_vers", &["-productVersion"]),
        board_vendor: Some("Apple Inc.".into()),
        board_name: None,
    };
    let cpu = CpuInventory {
        architecture: std::env::consts::ARCH.into(),
        model: command_output("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|| command_output("/usr/sbin/sysctl", &["-n", "hw.model"])),
        logical_cpu_count,
        physical_core_count,
        package_count: Some(1),
        packages,
    };
    let memory = MemoryInventory {
        total_bytes: command_output("/usr/sbin/sysctl", &["-n", "hw.memsize"])
            .and_then(|value| value.parse().ok()),
        available_bytes: macos_available_memory_bytes(),
    };
    let gpus = macos_gpus();
    let network_interfaces = macos_network_interfaces();
    let (disks, allocations) = macos_storage(data_paths);
    let subsystems = vec![
        status("system", "available", None),
        status("cpu", present(logical_cpu_count > 0), None),
        status("memory", present(memory.total_bytes.is_some()), None),
        status(
            "numa",
            "unsupported",
            Some("macOS does not expose host NUMA topology through Linux sysfs".into()),
        ),
        status(
            "pci",
            "unsupported",
            Some("macOS does not expose Linux PCI sysfs".into()),
        ),
        status("gpu", absent_or_available(!gpus.is_empty()), None),
        status("network", present(!network_interfaces.is_empty()), None),
        status("infiniband", "absent", None),
        status("disk", present(!disks.is_empty()), None),
        status("openlake_mapping", "available", None),
    ];
    HardwareSnapshot {
        schema_version: "1.0",
        collected_at_unix_ms: now_unix_ms(),
        collection_status: overall_status(&subsystems),
        system,
        cpu,
        memory,
        numa_nodes: Vec::new(),
        pci_devices: Vec::new(),
        gpus,
        network_interfaces,
        infiniband_devices: Vec::new(),
        disks,
        openlake: OpenLakeAllocation {
            kv_cache_capacity_bytes,
            data_paths: allocations,
        },
        subsystems,
    }
}

#[cfg(target_os = "macos")]
fn macos_available_memory_bytes() -> Option<u64> {
    command_output("/usr/bin/vm_stat", &[])
        .as_deref()
        .and_then(parse_macos_available_memory_bytes)
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_available_memory_bytes(output: &str) -> Option<u64> {
    let page_bytes = output
        .lines()
        .next()?
        .split("page size of ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    let pages = ["Pages free", "Pages inactive", "Pages speculative"]
        .into_iter()
        .filter_map(|field| {
            output.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.trim() == field)
                    .then(|| value.trim().trim_end_matches('.').parse::<u64>().ok())
                    .flatten()
            })
        })
        .try_fold(0_u64, u64::checked_add)?;
    pages.checked_mul(page_bytes)
}

#[cfg(target_os = "macos")]
fn macos_gpus() -> Vec<GpuDevice> {
    let Some(output) = command_output(
        "/usr/sbin/system_profiler",
        &["SPDisplaysDataType", "-json"],
    ) else {
        return Vec::new();
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(&output) else {
        return Vec::new();
    };
    document["SPDisplaysDataType"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, gpu)| GpuDevice {
            index: Some(index as u32),
            name: gpu["sppci_model"]
                .as_str()
                .or_else(|| gpu["_name"].as_str())
                .unwrap_or("Apple GPU")
                .to_owned(),
            vendor: "Apple".into(),
            uuid: None,
            pci_address: None,
            numa_node: None,
            memory_total_bytes: None,
            nvlinks: Vec::new(),
            source: "system_profiler / Metal".into(),
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn macos_network_interfaces() -> Vec<NetworkInterface> {
    let Some(names) = command_output("/sbin/ifconfig", &["-l"]) else {
        return Vec::new();
    };
    let mut interfaces = names
        .split_whitespace()
        .map(|name| {
            let detail = command_output("/sbin/ifconfig", &[name]).unwrap_or_default();
            NetworkInterface {
                name: name.to_owned(),
                mac_address: line_value(&detail, "ether "),
                operational_state: line_value(&detail, "status: "),
                mtu: detail
                    .lines()
                    .next()
                    .and_then(|line| line.split("mtu ").nth(1))
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse().ok()),
                speed_mbps: None,
                duplex: None,
                pci_address: None,
                numa_node: None,
                driver: None,
                infiniband_device: None,
            }
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    interfaces
}

#[cfg(target_os = "macos")]
fn line_value(text: &str, prefix: &str) -> Option<String> {
    text.lines().map(str::trim).find_map(|line| {
        line.strip_prefix(prefix)
            .map(|value| value.trim().to_owned())
    })
}

#[cfg(target_os = "macos")]
fn macos_storage(data_paths: &[PathBuf]) -> (Vec<DiskDevice>, Vec<DataPathAllocation>) {
    let mut disks = macos_disks();
    let mut allocations = Vec::new();
    for data_path in data_paths {
        let path = data_path.to_string_lossy();
        let output = command_output("/bin/df", &["-Pk", &path]);
        let fields = output
            .as_deref()
            .and_then(|output| output.lines().last())
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .unwrap_or_default();
        let source = fields.first().map(|value| (*value).to_owned());
        let mount_point = fields.last().map(|value| (*value).to_owned());
        if let Some(source) = source.as_ref() {
            if !disks
                .iter()
                .any(|disk: &DiskDevice| disk.device_path == *source)
            {
                disks.push(DiskDevice {
                    name: Path::new(source)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| source.clone()),
                    device_path: source.clone(),
                    major_minor: None,
                    size_bytes: fields
                        .get(1)
                        .and_then(|value| value.parse::<u64>().ok())
                        .and_then(|kib| kib.checked_mul(1024)),
                    rotational: None,
                    vendor: Some("Apple".into()),
                    model: None,
                    transport: None,
                    pci_address: None,
                    numa_node: None,
                });
            }
        }
        let backing_disk = source.as_deref().and_then(|source| {
            let detail = command_output("/usr/sbin/diskutil", &["info", source])?;
            line_value(&detail, "APFS Physical Store:")
                .or_else(|| line_value(&detail, "Device Identifier:"))
                .map(|device| whole_disk_name(&device))
        });
        allocations.push(DataPathAllocation {
            path: path.into_owned(),
            mount_point,
            filesystem: None,
            source: source.clone(),
            device: source.clone(),
            disk: backing_disk.or_else(|| source.map(|source| whole_disk_name(&source))),
        });
    }
    (disks, allocations)
}

#[cfg(target_os = "macos")]
fn macos_disks() -> Vec<DiskDevice> {
    let Some(output) = command_output("/usr/sbin/diskutil", &["list", "physical"]) else {
        return Vec::new();
    };
    output
        .lines()
        .filter_map(|line| line.trim().strip_suffix(" (internal, physical):"))
        .map(str::to_owned)
        .map(|device_path| {
            let detail =
                command_output("/usr/sbin/diskutil", &["info", &device_path]).unwrap_or_default();
            let name = Path::new(&device_path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| device_path.clone());
            DiskDevice {
                name,
                device_path,
                major_minor: None,
                size_bytes: line_value(&detail, "Disk Size:")
                    .as_deref()
                    .and_then(parenthesized_bytes),
                rotational: line_value(&detail, "Solid State:")
                    .map(|value| !value.eq_ignore_ascii_case("yes")),
                vendor: Some("Apple".into()),
                model: line_value(&detail, "Device / Media Name:"),
                transport: line_value(&detail, "Protocol:"),
                pci_address: None,
                numa_node: None,
            }
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn parenthesized_bytes(value: &str) -> Option<u64> {
    let start = value.find('(')? + 1;
    let end = value[start..].find(" Bytes")? + start;
    value[start..end].trim().parse().ok()
}

#[cfg(target_os = "macos")]
fn whole_disk_name(value: &str) -> String {
    let name = Path::new(value)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| value.to_owned());
    let bytes = name.as_bytes();
    for index in 4..bytes.len() {
        if bytes[index] == b's' && bytes[index + 1..].iter().all(u8::is_ascii_digit) {
            return name[..index].to_owned();
        }
    }
    name
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_portable(
    data_paths: &[PathBuf],
    kv_cache_capacity_bytes: Option<u64>,
) -> HardwareSnapshot {
    let system = basic_system(std::env::consts::OS);
    let logical_cpu_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(0);
    let subsystems = vec![
        status("system", "partial", None),
        status("cpu", present(logical_cpu_count > 0), None),
        status("memory", "unsupported", None),
        status("numa", "unsupported", None),
        status("pci", "unsupported", None),
        status("gpu", "unsupported", None),
        status("network", "unsupported", None),
        status("infiniband", "unsupported", None),
        status("disk", "unsupported", None),
        status("openlake_mapping", "partial", None),
    ];
    HardwareSnapshot {
        schema_version: "1.0",
        collected_at_unix_ms: now_unix_ms(),
        collection_status: overall_status(&subsystems),
        system,
        cpu: CpuInventory {
            architecture: std::env::consts::ARCH.into(),
            model: None,
            logical_cpu_count,
            physical_core_count: None,
            package_count: None,
            packages: Vec::new(),
        },
        memory: MemoryInventory::default(),
        numa_nodes: Vec::new(),
        pci_devices: Vec::new(),
        gpus: Vec::new(),
        network_interfaces: Vec::new(),
        infiniband_devices: Vec::new(),
        disks: Vec::new(),
        openlake: OpenLakeAllocation {
            kv_cache_capacity_bytes,
            data_paths: data_paths
                .iter()
                .map(|path| DataPathAllocation {
                    path: path.to_string_lossy().into_owned(),
                    mount_point: None,
                    filesystem: None,
                    source: None,
                    device: None,
                    disk: None,
                })
                .collect(),
        },
        subsystems,
    }
}

fn present(available: bool) -> &'static str {
    if available {
        "available"
    } else {
        "unavailable"
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn absent_or_available(available: bool) -> &'static str {
    if available {
        "available"
    } else {
        "absent"
    }
}

fn status(
    subsystem: &'static str,
    status: &'static str,
    detail: Option<String>,
) -> SubsystemStatus {
    SubsystemStatus {
        subsystem,
        status,
        detail,
    }
}

fn overall_status(subsystems: &[SubsystemStatus]) -> String {
    if subsystems
        .iter()
        .any(|subsystem| matches!(subsystem.status, "unavailable" | "partial" | "unsupported"))
    {
        "partial"
    } else {
        "available"
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_linux_cpu_ranges() {
        assert_eq!(parse_cpu_list("0-3,8,10-11"), vec![0, 1, 2, 3, 8, 10, 11]);
    }

    #[test]
    fn validates_pci_addresses() {
        assert!(is_pci_address("0000:65:00.0"));
        assert!(!is_pci_address("65:00.0"));
        assert!(!is_pci_address("0000:zz:00.0"));
    }

    #[test]
    fn resolves_known_pci_vendors() {
        assert_eq!(pci_vendor_display_name(Some("10de")), Some("NVIDIA"));
        assert_eq!(
            pci_vendor_display_name(Some("15B3")),
            Some("NVIDIA Networking")
        );
        assert_eq!(pci_vendor_display_name(Some("ffff")), None);
    }

    #[test]
    fn parses_linux_and_numa_meminfo() {
        assert_eq!(
            meminfo_bytes("MemTotal: 1024 kB", "MemTotal"),
            Some(1_048_576)
        );
        assert_eq!(
            meminfo_bytes("Node 0 MemTotal: 2048 kB", "MemTotal"),
            Some(2_097_152)
        );
    }

    #[test]
    fn parses_macos_available_memory() {
        let vm_stat = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 10.\nPages active: 100.\nPages inactive: 20.\nPages speculative: 5.\n";
        assert_eq!(
            parse_macos_available_memory_bytes(vm_stat),
            Some(35 * 16_384)
        );
    }
}
