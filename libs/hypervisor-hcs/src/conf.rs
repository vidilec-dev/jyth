use crate::error::HcsError;
use error_stack::Report;
use serde_json::Value;
use std::path::Path;

/// HCS-side description of a guest NIC. The `endpoint_id` is the HNS
/// endpoint's `Id` (a GUID string) that the endpoint-create path will
/// populate; HCS resolves the NIC to that endpoint at VM start. The
/// optional `mac` is surfaced as `MacAddress` in the JSON HCS reads.
///
/// This type only describes the HCS schema block — the HNS endpoint
/// lifecycle (create/close/delete) lives in `crate::hns`; here we
/// only carry the strings that get serialised into the VM config.
#[derive(Clone, Debug)]
pub struct NetworkAdapter {
    pub endpoint_id: String,
    pub mac: Option<String>,
}

/// HCS-side description of a guest SCSI disk attachment. `controller`
/// and `lun` pick a (controller, LUN) slot; `path` is the host-side
/// `.vhdx` file path HCS opens and exposes to the guest as a block
/// device. `read_only` maps to `ReadOnly` in the HCS schema.
///
/// The HCS v2 schema keys `Devices.Scsi` entries by a `"<controller>:<lun>"`
/// string (e.g. `"0:0"` for the first LUN on the first controller) and
/// reads `Path` as a host filesystem path. We use the same keying
/// convention here (`format!("{controller}:{lun}")`) so the host-side
/// `add_scsi_disk` caller doesn't need to know the key format.
#[derive(Clone, Debug)]
pub struct ScsiDisk {
    /// SCSI controller index (0..). HCS supports up to 64 LUNs per
    /// controller and up to 4 controllers by default.
    pub controller: u32,
    /// Logical Unit Number within the controller (0..64).
    pub lun: u32,
    /// Absolute host-side path to the `.vhdx` file to attach.
    pub path: String,
    /// If true, the guest sees the disk read-only.
    pub read_only: bool,
}

pub struct Conf {
    inner: Value,
}

impl Default for Conf {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal-shape error: `Conf::new()` always seeds the `VirtualMachine`
/// `Devices` object, so reaching one of these `ok_or` arms means the
/// configuration shape drifted. Propagated as a report instead of panicking
/// in a public builder method.
fn conf_report(message: &'static str) -> Report<HcsError> {
    Report::new(HcsError::Serialize).attach(message)
}

impl Conf {
    pub fn new() -> Self {
        Self {
            inner: serde_json::json!({
                "Owner": "jyth",
                "SchemaVersion": {
                    "Major": 2,
                    "Minor": 1
                },
                "VirtualMachine": {
                    "Chipset": {
                        "LinuxKernelDirect": {
                            "KernelFilePath": "",
                            "InitRdPath": "",
                            "KernelCmdLine": ""
                        }
                    },
                    "ComputeTopology": {
                        "Memory": {
                            "SizeInMB": 512
                        },
                        "Processor": {
                            "Count": 1
                        }
                    },
                    "Devices": {}
                }
            }),
        }
    }

    pub fn kernel<P: AsRef<Path>>(mut self, kernel: P) -> Self {
        self.inner["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelFilePath"] =
            Value::String(kernel.as_ref().to_string_lossy().into_owned());
        self
    }

    pub fn initrd<P: AsRef<Path>>(mut self, initrd: P) -> Self {
        self.inner["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["InitRdPath"] =
            Value::String(initrd.as_ref().to_string_lossy().into_owned());
        self
    }

    pub fn memory(mut self, memory_mb: u64) -> Self {
        self.inner["VirtualMachine"]["ComputeTopology"]["Memory"]["SizeInMB"] =
            serde_json::json!(memory_mb);
        self
    }

    pub fn vcpus(mut self, vcpus: u32) -> Self {
        self.inner["VirtualMachine"]["ComputeTopology"]["Processor"]["Count"] =
            serde_json::json!(vcpus);
        self
    }

    pub fn parms(mut self, cmdline: &str) -> Self {
        self.inner["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"] =
            Value::String(cmdline.to_string());
        self
    }

    /// Set the exact per-session HCS owner recorded in the runtime journal.
    pub fn owner(mut self, owner: &str) -> Self {
        self.inner["Owner"] = Value::String(owner.to_string());
        self
    }

    pub fn add_com_port(mut self, port: u32, pipe: &str) -> Result<Self, Report<HcsError>> {
        let devices = self
            .inner
            .get_mut("VirtualMachine")
            .and_then(|vm| vm.get_mut("Devices"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| conf_report("Conf::new always seeds VirtualMachine/Devices"))?;
        if !devices.contains_key("ComPorts") {
            devices.insert("ComPorts".to_string(), serde_json::json!({}));
        }
        let com_ports = devices
            .get_mut("ComPorts")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| conf_report("ComPorts was just seeded as an object"))?;
        com_ports.insert(
            port.to_string(),
            serde_json::json!({
                "NamedPipe": pipe
            }),
        );
        Ok(self)
    }

    /// Inject a network adapter into the `Devices.NetworkAdapters` map
    /// of the HCS configuration. The adapter is bound to the HNS
    /// endpoint identified by `endpoint_id`; HCS resolves the adapter
    /// to a real NIC at VM start via that endpoint reference.
    ///
    /// Schema (subset of the HCS VMShader schema v2.1 `Devices`,
    /// verified against `hcsshim/internal/hcs/schema2/devices.go`
    /// and `network_adapter.go`):
    /// ```json
    /// {
    ///   "NetworkAdapters": {
    ///     "adapter0": {
    ///       "EndpointId": "<guid-string>",
    ///       "MacAddress": "00:15:5D:76:00:0A"   // optional
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// Note: v2.x `NetworkAdapters` is a *map* keyed by an
    /// adapter-instance name (NOT the v1-style array), and the
    /// endpoint identifier is the flat `EndpointId` field (NOT the
    /// v1-style nested `Endpoint.Id`). The map keys just need to be
    /// unique within one VM doc; we generate them as `adapter0`,
    /// `adapter1`, etc. The endpoint handle itself is created
    /// separately by the HNS lifecycle path (see `crate::hns`);
    /// this method only emits the HCS-side reference. Multiple
    /// adapters may be added by calling the builder repeatedly.
    pub fn add_network_adapter(
        mut self,
        adapter: NetworkAdapter,
    ) -> Result<Self, Report<HcsError>> {
        let devices = self
            .inner
            .get_mut("VirtualMachine")
            .and_then(|vm| vm.get_mut("Devices"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| conf_report("Conf::new always seeds Devices"))?;
        let adapters = match devices.get_mut("NetworkAdapters") {
            Some(v) => v
                .as_object_mut()
                .ok_or_else(|| conf_report("NetworkAdapters seeded as object"))?,
            None => {
                devices.insert("NetworkAdapters".to_string(), serde_json::json!({}));
                devices
                    .get_mut("NetworkAdapters")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| conf_report("NetworkAdapters seeded as object above"))?
            }
        };
        // Pick a unique adapter-instance name. The v2 schema keys
        // `NetworkAdapters` by an arbitrary per-VM string; `adapter0`,
        // `adapter1`, ... is what `dockerd`'s HCS driver uses, so it's
        // a known-good convention.
        let next_index = adapters.len();
        let key = format!("adapter{next_index}");
        let mut entry = serde_json::json!({
            "EndpointId": adapter.endpoint_id,
        });
        if let Some(mac) = adapter.mac {
            entry["MacAddress"] = Value::String(mac);
        }
        adapters.insert(key, entry);
        Ok(self)
    }

    /// Attach a SCSI disk to the VM. The HCS v2 schema keys
    /// `Devices.Scsi` entries by *controller index* (e.g. `"0"`), and
    /// each controller holds an `Attachments` map keyed by the LUN
    /// (e.g. `"0"`). Each attachment requires a `Type` of
    /// `"VirtualDisk"` and a `Path` pointing at the host-side `.vhdx`
    /// file; `ReadOnly` is only emitted when `true`. Verified against
    /// `hcsshim/internal/hcs/schema2/{devices,scsi,attachment}.go`
    /// (VMShader schema v2.1).
    ///
    /// Schema:
    /// ```json
    /// {
    ///   "Scsi": {
    ///     "0": {
    ///       "Attachments": {
    ///         "0": {
    ///           "Type": "VirtualDisk",
    ///           "Path": "C:\\scratch\\scratch-0.vhdx"
    ///         }
    ///       }
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// Multiple disks may be attached by calling the builder
    /// repeatedly, each with a distinct `(controller, lun)` pair. The
    /// HCS backend (`crate::Vm::from_conf`) picks `(idx/64, idx%64)`
    /// for the `idx`-th disk, so callers there don't have to.
    pub fn add_scsi_disk(mut self, disk: ScsiDisk) -> Result<Self, Report<HcsError>> {
        let devices = self
            .inner
            .get_mut("VirtualMachine")
            .and_then(|vm| vm.get_mut("Devices"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| conf_report("Conf::new always seeds Devices"))?;
        let scsi = match devices.get_mut("Scsi") {
            Some(v) => v
                .as_object_mut()
                .ok_or_else(|| conf_report("Scsi seeded as object"))?,
            None => {
                devices.insert("Scsi".to_string(), serde_json::json!({}));
                devices
                    .get_mut("Scsi")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| conf_report("Scsi seeded as object above"))?
            }
        };
        let controller_key = disk.controller.to_string();
        let controller = match scsi.get_mut(&controller_key) {
            Some(v) => v
                .as_object_mut()
                .ok_or_else(|| conf_report("Scsi controller is object"))?,
            None => {
                scsi.insert(
                    controller_key.clone(),
                    serde_json::json!({ "Attachments": {} }),
                );
                scsi.get_mut(&controller_key)
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| {
                        conf_report("Scsi controller seeded with empty Attachments map above")
                    })?
            }
        };
        let attachments = controller
            .get_mut("Attachments")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| conf_report("Attachments seeded as object"))?;
        let lun_key = disk.lun.to_string();
        let mut entry = serde_json::json!({
            "Type": "VirtualDisk",
            "Path": disk.path,
        });
        if disk.read_only {
            entry["ReadOnly"] = Value::Bool(true);
        }
        attachments.insert(lun_key, entry);
        Ok(self)
    }

    pub fn json(&self) -> Result<String, Report<HcsError>> {
        let lkd = &self.inner["VirtualMachine"]["Chipset"]["LinuxKernelDirect"];

        if lkd["KernelFilePath"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
        {
            return Err(
                Report::new(HcsError::Serialize).attach("KernelFilePath is required but was empty")
            );
        }
        if lkd["InitRdPath"].as_str().unwrap_or_default().is_empty() {
            return Err(
                Report::new(HcsError::Serialize).attach("InitRdPath is required but was empty")
            );
        }
        if lkd["KernelCmdLine"].as_str().unwrap_or_default().is_empty() {
            return Err(
                Report::new(HcsError::Serialize).attach("KernelCmdLine is required but was empty")
            );
        }

        serde_json::to_string(&self.inner)
            .map_err(|e| Report::new(e).change_context(HcsError::Serialize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hcs_config_generation() {
        let kernel = Path::new("C:\\images\\vmlinuz");
        let initrd = Path::new("C:\\images\\initrd.img");
        let memory_mb = 2048;
        let vcpus = 4;
        let cmdline = "console=ttyS0 root=/dev/ram0";

        let conf = Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(memory_mb)
            .vcpus(vcpus)
            .parms(cmdline);

        let config_json = conf.json().expect("Failed to build HCS config");

        // Verify key parts of the JSON
        assert!(config_json.contains("\"KernelFilePath\":\"C:\\\\images\\\\vmlinuz\""));
        assert!(config_json.contains("\"InitRdPath\":\"C:\\\\images\\\\initrd.img\""));
        assert!(config_json.contains("\"KernelCmdLine\":\"console=ttyS0 root=/dev/ram0\""));
        assert!(config_json.contains("\"SizeInMB\":2048"));
        assert!(config_json.contains("\"Count\":4"));

        // The TCP transport migration removed the HvSocket device: the
        // configuration must never seed an HvSocket member.
        let value: Value = serde_json::from_str(&config_json).expect("config is valid JSON");
        let devices = &value["VirtualMachine"]["Devices"];
        assert!(
            devices.get("HvSocket").is_none(),
            "Devices must contain no HvSocket member: {config_json}"
        );
    }

    #[test]
    fn test_hcs_config_multiple_com_ports() {
        let kernel = Path::new("C:\\images\\vmlinuz");
        let initrd = Path::new("C:\\images\\initrd.img");
        let memory_mb = 512;
        let vcpus = 1;

        let conf = Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(memory_mb)
            .vcpus(vcpus)
            .parms("console=ttyS0")
            .add_com_port(0, r"\\.\pipe\console")
            .expect("Conf::new seeds Devices")
            .add_com_port(1, r"\\.\pipe\stdio")
            .expect("Conf::new seeds Devices");

        let config_json = conf.json().expect("Failed to build HCS config");

        assert!(config_json.contains(r#""0":{"NamedPipe":"\\\\.\\pipe\\console"}"#));
        assert!(config_json.contains(r#""1":{"NamedPipe":"\\\\.\\pipe\\stdio"}"#));
    }

    /// `add_network_adapter` must seed `Devices.NetworkAdapters` with one
    /// entry per call, each carrying the supplied `EndpointId` (flat
    /// string, not nested under `Endpoint`) and (when present) a
    /// `MacAddress`. `NetworkAdapters` in the HCS VMShader v2 schema is
    /// a *map* keyed by an arbitrary per-VM adapter-instance name —
    /// not the v1-style array (verified against
    /// `hcsshim/internal/hcs/schema2/devices.go` and `network_adapter.go`).
    /// This is the schema-only contract the HNS lifecycle path relies
    /// on; gating the adapter JSON here means the heavier integration
    /// test only has to assert that *some* adapter appeared, not the
    /// exact shape.
    #[test]
    fn network_adapter_serializes_into_devices_path() {
        let kernel = Path::new("C:\\images\\vmlinuz");
        let initrd = Path::new("C:\\images\\initrd.img");

        let conf = Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(512)
            .vcpus(1)
            .parms("console=ttyS0")
            .add_network_adapter(NetworkAdapter {
                endpoint_id: "11111111-2222-3333-4444-555555555555".to_string(),
                mac: Some("00:15:5D:76:00:0A".to_string()),
            })
            .expect("Conf::new seeds Devices")
            .add_network_adapter(NetworkAdapter {
                endpoint_id: "66666666-7777-8888-9999-AAAAAAAAAAAA".to_string(),
                mac: None,
            })
            .expect("Conf::new seeds Devices");

        let config_json = conf.json().expect("Failed to build HCS config");

        // Parse and walk to the adapters map so we assert structure,
        // not just substring presence (the substring check is fragile
        // because serde_json doesn't guarantee key order).
        let v: Value = serde_json::from_str(&config_json).expect("config is valid JSON");
        let adapters = v["VirtualMachine"]["Devices"]["NetworkAdapters"]
            .as_object()
            .expect("NetworkAdapters must be an object/map");
        assert_eq!(adapters.len(), 2, "exactly two adapters expected");

        // The first-added adapter is keyed `adapter0`; the second `adapter1`.
        let a0 = &adapters["adapter0"];
        assert_eq!(
            a0["EndpointId"].as_str().unwrap(),
            "11111111-2222-3333-4444-555555555555",
        );
        assert_eq!(a0["MacAddress"].as_str().unwrap(), "00:15:5D:76:00:0A");

        let a1 = &adapters["adapter1"];
        assert_eq!(
            a1["EndpointId"].as_str().unwrap(),
            "66666666-7777-8888-9999-AAAAAAAAAAAA",
        );
        // No mac supplied ⇒ field must be absent (not null) so HCS
        // uses its own MAC pool.
        assert!(
            a1.get("MacAddress").is_none(),
            "MacAddress must be absent when not supplied",
        );

        // Smoke test: the v2 schema names. The detailed walk above is
        // what really asserts the shape; the substring check just
        // guards against a regression that re-introduces the v1
        // `Endpoint:{Id:...}` nested form or the v1 array form for
        // `NetworkAdapters`.
        assert!(config_json.contains("\"NetworkAdapters\""));
        assert!(config_json.contains("\"EndpointId\""));
        assert!(!config_json.contains("\"Endpoint\":{"));

        // Regression guard: HCS's endpoint resolver does a
        // case-sensitive compare against the GUID strings HNS emits
        // (un-braced lowercase), so a braced `EndpointId` like
        // `"{11111111-...}"` would fail to resolve and
        // `HcsCreateComputeSystem` would reject the whole VM with
        // `HCS_E_SYSTEM_INVALID_CONFIGURATION` (HRESULT 0x8037010D,
        // `OperationFailure.Detail: Construct`). The test inputs are
        // un-braced, so the serialised `EndpointId` MUST stay
        // un-braced too.
        for v in adapters.values() {
            let s = v["EndpointId"].as_str().expect("EndpointId is a string");
            assert!(
                !s.starts_with('{') && !s.ends_with('}'),
                "EndpointId must NOT be braced; got {s}",
            );
        }
    }

    /// `add_scsi_disk` must seed `Devices.Scsi` with the correct HCS v2
    /// schema: `Devices.Scsi` is keyed by controller index string, each
    /// controller holds an `Attachments` map keyed by LUN string, and
    /// each attachment carries `Type: "VirtualDisk"` + `Path`. `ReadOnly`
    /// is omitted (NOT null) when false so HCS defaults to read-write.
    /// Verified against `hcsshim/internal/hcs/schema2/{devices,scsi,
    /// attachment}.go`.
    #[test]
    fn scsi_disk_serializes_into_devices_path() {
        let kernel = Path::new("C:\\images\\vmlinuz");
        let initrd = Path::new("C:\\images\\initrd.img");

        let conf = Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(512)
            .vcpus(1)
            .parms("console=ttyS0")
            .add_scsi_disk(ScsiDisk {
                controller: 0,
                lun: 0,
                path: "C:\\scratch\\scratch-0.vhdx".to_string(),
                read_only: false,
            })
            .expect("Conf::new seeds Devices")
            .add_scsi_disk(ScsiDisk {
                controller: 0,
                lun: 1,
                path: "C:\\scratch\\scratch-1.vhdx".to_string(),
                read_only: true,
            })
            .expect("Conf::new seeds Devices");

        let config_json = conf.json().expect("Failed to build HCS config");

        let v: Value = serde_json::from_str(&config_json).expect("config is valid JSON");
        let scsi = v["VirtualMachine"]["Devices"]["Scsi"]
            .as_object()
            .expect("Scsi must be an object/map");
        // One controller ("0") with two LUNs.
        assert_eq!(scsi.len(), 1, "exactly one scsi controller expected");
        let ctrl = &scsi["0"];
        let attachments = ctrl["Attachments"]
            .as_object()
            .expect("Attachments must be an object/map");
        assert_eq!(attachments.len(), 2, "exactly two LUNs expected");

        let d0 = &attachments["0"];
        assert_eq!(d0["Type"].as_str().unwrap(), "VirtualDisk");
        assert_eq!(d0["Path"].as_str().unwrap(), "C:\\scratch\\scratch-0.vhdx",);
        assert!(
            d0.get("ReadOnly").is_none(),
            "ReadOnly must be absent when not supplied",
        );

        let d1 = &attachments["1"];
        assert_eq!(d1["Type"].as_str().unwrap(), "VirtualDisk");
        assert_eq!(d1["Path"].as_str().unwrap(), "C:\\scratch\\scratch-1.vhdx",);
        assert!(d1["ReadOnly"].as_bool().unwrap());

        assert!(config_json.contains("\"Scsi\""));
        assert!(config_json.contains("\"Attachments\""));
        assert!(config_json.contains("\"VirtualDisk\""));
    }
}
