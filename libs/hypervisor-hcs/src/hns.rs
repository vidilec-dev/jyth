//! Raw FFI bindings to the Host Compute Network (HCN) API — the network
//! management surface that complements the HCS compute-system API in
//! [`crate::ext`]. Where `ext.rs` talks to the `computecore` DLL
//! to create/start/stop VMs, this module talks to the `computenetwork`
//! DLL to create/delete HNS networks and endpoints.
//!
//! The HCN API surface used here is:
//!
//! - [`HcnCreateNetwork`]         / [`HcnCloseNetwork`]         / [`HcnDeleteNetwork`]
//! - [`HcnCreateEndpoint`]        / [`HcnCloseEndpoint`]        / [`HcnDeleteEndpoint`]
//! - [`HcnQueryEndpointProperties`] to retrieve the endpoint identity HCS
//!   needs in its configuration
//!
//! After [`HcnCreateEndpoint`] the *endpoint* GUID actually allocated by HNS
//! is found by querying the endpoint back — the GUID the caller supplies to
//! `HcnCreateEndpoint` is advisory and HNS is free to assign its own. Runtime
//! recovery uses exact IDs when available and falls back only to the exact
//! deterministic names stored in the durable session journal; it never scans
//! prefixes or deletes by owner tag.
//!
//! # Signature alignment
//!
//! The signatures match the Microsoft HCN C reference exactly
//! (<https://learn.microsoft.com/en-us/virtualization/api/hcn/reference/hcncreatenetwork>):
//!
//! - First arg of every create/delete is a **`REFGUID`** — a 16-byte
//!   Windows `GUID` pointer identifying the network/endpoint, **not**
//!   a `PCWSTR` name. The human-readable name lives inside the JSON
//!   `Settings` document (`"Name":"..."`).
//! - Every create/delete takes a final **`ErrorRecord`** out-param
//!   (`*mut *mut u16`); on failure HNS writes a JSON diagnostics
//!   document there which the caller must release with `CoTaskMemFree`.
//!   Surfacing that text in the typed `HcsError::Network` makes
//!   debugging `0x803B001B`-style schema rejections immediate instead
//!   of "guess what HNS didn't like about my JSON."
//!
//! Each `Hcn*` call returns an `HRESULT`; handles are `*mut c_void`
//! opaque pointers, closed by their respective `HcnClose*` calls. The
//! handle lifetime management lives in `create_network_and_endpoint_with_callbacks`
//! / `close_and_delete_result`; this file only binds the raw symbols.
//!
//! # Safety
//!
//! The signatures match the Microsoft HCN C API exactly. Callers are
//! responsible for the JSON pointer strings outliving the call, for
//! passing a valid 16-byte aligned `GUID`, and for closing every
//! successfully-opened handle exactly once. The `ErrorRecord` buffer,
//! when non-null on return, must be released with `CoTaskMemFree`.
//!
//! # Why raw FFI and not `windows-sys`?
//!
//! Mirrors [`crate::ext`]: the existing crate uses raw `extern
//! "system"` blocks against `computecore` rather than pulling
//! `windows-sys`, and keeping the network FFI in the same style avoids
//! introducing a second binding mechanism just for HNS. The HCN API
//! is exported by `computenetwork.dll`, which already ships on every
//! supported Windows host (the same DLL WSL/HCS-Docker use).

#![allow(non_camel_case_types)]

use std::ffi::c_void;

/// Opaque handle to an HNS network, returned by [`HcnCreateNetwork`] and
/// closed by [`HcnCloseNetwork`]. Semantically equivalent to
/// `HCS_SYSTEM` in [`crate::ext`]; we keep the type distinct so a
/// compute-system handle can't be accidentally passed where a network
/// handle is expected.
#[allow(non_camel_case_types)]
pub type HCN_NETWORK = *mut c_void;

/// Opaque handle to an HNS endpoint.
#[allow(non_camel_case_types)]
pub type HCN_ENDPOINT = *mut c_void;

/// `HRESULT` indicating the operation is still in progress — mirrors the
/// `HCS_E_OPERATION_PENDING` constant used by the steering APIs. HCN
/// calls are synchronous (the `Hcn*` family does not have a `Hcn*Async`
/// counterpart in this binding) but the constant is exported anyway for
/// parity with [`crate::ext::HCS_E_OPERATION_PENDING`] and for
/// future use of the async variants.
#[allow(dead_code)]
pub const HCN_E_OPERATION_PENDING: i32 = 0x80370120_u32 as i32;

/// `S_OK` — every HCN call returns this on success. Defined locally to
/// avoid pulling `Win32_Foundation` just for the one constant.
#[allow(dead_code)]
pub const S_OK: i32 = 0;

/// Windows `GUID` (`{data1: u32, data2: u16, data3: u16, data4: [u8; 8]}`),
/// matching the host `REFGUID` ABI exactly so a `*const Guid` can be
/// passed where a Windows `REFGUID` is expected. The layout is the same
/// as the `windows-sys` `GUID` and the Win32 `GUID` struct — no padding,
/// no Rust-side `#[repr(Rust)]` surprises — verified by the
/// `guid_layout_is_windows_compat` compile-time assertion below.
///
/// Built from a `uuid::Uuid` via the [`Guid::from_uuid`] constructor;
/// the conversion is byte-exact because `uuid::Uuid`'s internal layout
/// is also `[u8; 16]` (RFC 4122 byte order).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Build a `Guid` from a `uuid::Uuid`. The `Uuid`'s fields are
    /// accessed via the platform-independent accessor (the
    /// `Uuid::as_fields` method returns `(u32, u16, u16, &[u8; 8])`
    /// in the same layout Windows uses), so the conversion is portable
    /// across big- and little-endian hosts.
    pub fn from_uuid(u: &uuid::Uuid) -> Self {
        let (data1, data2, data3, data4) = u.as_fields();
        Self {
            data1,
            data2,
            data3,
            data4: *data4,
        }
    }
}

const _: () = {
    // Compile-time layout check: the Windows `GUID` is exactly 16 bytes
    // with no alignment-larger-than-4 fields, so the only thing left to
    // assert is the size. Alignment is implied by `#[repr(C)]` on a
    // struct whose largest member is `u32`.
    assert!(std::mem::size_of::<Guid>() == 16);
};

#[link(name = "computenetwork")]
#[allow(dead_code)] // consumed by the HNS lifecycle module below
unsafe extern "system" {
    /// Create a network. On success, `*network_handle` receives an owned
    /// handle the caller must close with [`HcnCloseNetwork`].
    ///
    /// Args (per Microsoft HCN reference):
    /// - `id`: `REFGUID` identifying the new network. **Not** a name —
    ///   the name lives inside the `settings` JSON document.
    /// - `settings`: UTF-16 JSON settings document (SchemaVersion 2.x).
    /// - `network_handle`: out-param receiving the new handle.
    /// - `error_record`: out-param receiving a JSON diagnostics
    ///   document on failure (caller frees with `CoTaskMemFree`).
    pub fn HcnCreateNetwork(
        id: *const Guid,
        settings: *const u16,
        network_handle: *mut HCN_NETWORK,
        error_record: *mut *mut u16,
    ) -> i32;

    /// Close an open network handle. After this returns, the handle must
    /// not be reused; the underlying HNS network itself is *not* deleted
    /// (use [`HcnDeleteNetwork`] for that).
    ///
    /// Per the reference, `HcnCloseNetwork` only takes the handle (no
    /// error out-param).
    pub fn HcnCloseNetwork(network: HCN_NETWORK) -> i32;

    /// Enumerate networks matching a HostComputeQuery. The returned JSON is
    /// owned by HCN and must be released with `CoTaskMemFree`.
    pub fn HcnEnumerateNetworks(
        query: *const u16,
        networks: *mut *mut u16,
        error_record: *mut *mut u16,
    ) -> i32;

    /// Open a network by its exact GUID so its properties can be checked
    /// before a name-based recovery fallback deletes it.
    pub fn HcnOpenNetwork(
        id: *const Guid,
        network_handle: *mut HCN_NETWORK,
        error_record: *mut *mut u16,
    ) -> i32;

    /// Query an open network's properties, including its exact name.
    pub fn HcnQueryNetworkProperties(
        network: HCN_NETWORK,
        query: *const u16,
        properties_buffer: *mut *mut u16,
        error_record: *mut *mut u16,
    ) -> i32;

    /// Delete a network by GUID. The network must have no attached
    /// endpoints (close + delete all endpoints first). Best-effort;
    /// returns `HRESULT_FROM_WIN32(ERROR_BUSY)` if the network is in
    /// use. The `id` is a `REFGUID` matching the one passed to
    /// [`HcnCreateNetwork`].
    pub fn HcnDeleteNetwork(id: *const Guid, error_record: *mut *mut u16) -> i32;

    /// Create an endpoint on a network. On success, `*endpoint_handle`
    /// receives an owned handle. When the settings document contains
    /// `"Attach": true` HNS attaches the endpoint to the referenced
    /// VM at create time, so no separate hot-plug is needed.
    ///
    /// Args (per hcsshim binding of the Microsoft HCN reference):
    /// - `network`: handle of the parent network (from
    ///   [`HcnCreateNetwork`]); HNS identifies the parent this way,
    ///   *not* by a GUID pointer — the Go binding's `hcnCreateEndpoint`
    ///   signature is
    ///   `hcnCreateEndpoint(network, &endpointID, settings, &ep, &err)`.
    /// - `endpoint_id`: `*mut REFGUID` — HNS writes the freshly-allocated
    ///   endpoint GUID into this out-param if the caller passes a
    ///   zero-initialized GUID (matches hcsshim's `endpointID := guid.GUID{}`
    ///   pattern). We rely on the same: pass a zero GUID, HNS fills it.
    /// - `settings`: UTF-16 JSON settings document (SchemaVersion 2.x).
    /// - `endpoint_handle`: out-param receiving the new handle.
    /// - `error_record`: out-param receiving a JSON diagnostics
    ///   document on failure.
    pub fn HcnCreateEndpoint(
        network: HCN_NETWORK,
        endpoint_id: *mut Guid,
        settings: *const u16,
        endpoint_handle: *mut HCN_ENDPOINT,
        error_record: *mut *mut u16,
    ) -> i32;

    /// Close an open endpoint handle. Does not detach the endpoint from
    /// any VM it's attached to; use [`HcnDeleteEndpoint`] for full
    /// teardown. Per the reference, takes only the handle.
    pub fn HcnCloseEndpoint(endpoint: HCN_ENDPOINT) -> i32;

    /// Enumerate endpoints matching a HostComputeQuery. The returned JSON is
    /// owned by HCN and must be released with `CoTaskMemFree`.
    pub fn HcnEnumerateEndpoints(
        query: *const u16,
        endpoints: *mut *mut u16,
        error_record: *mut *mut u16,
    ) -> i32;

    /// Open an endpoint by its exact GUID so its properties can be checked
    /// before a name-based recovery fallback deletes it.
    pub fn HcnOpenEndpoint(
        id: *const Guid,
        endpoint_handle: *mut HCN_ENDPOINT,
        error_record: *mut *mut u16,
    ) -> i32;

    /// Delete an endpoint by GUID. Detaches the endpoint from any VM
    /// and frees the HNS-side state. Per the Microsoft HCN reference
    /// and the hcsshim binding
    /// (`hcnDeleteEndpoint(&endpointGUID, &resultBuffer)`), the call
    /// takes only the endpoint's GUID and an error out-param — the
    /// parent network is implicit (the endpoint GUID is globally
    /// unique).
    pub fn HcnDeleteEndpoint(endpoint_id: *const Guid, error_record: *mut *mut u16) -> i32;

    /// Query the properties of an open endpoint handle. `query` is an
    /// `HostComputeQuery` JSON document (an empty `SchemaVersion v2.0`
    /// query with no flags returns the standard properties); on success
    /// `*properties_buffer` receives a `CoTaskMemAlloc`-backed JSON
    /// document describing the endpoint. We use this after
    /// [`HcnCreateEndpoint`] to read back the `ID` field — i.e. the
    /// GUID HNS actually allocated to the endpoint — and the `Name`
    /// field for orphan-filter matching. Mirrors hcsshim's
    /// `hcnQueryEndpointProperties`.
    pub fn HcnQueryEndpointProperties(
        endpoint: HCN_ENDPOINT,
        query: *const u16,
        properties_buffer: *mut *mut u16,
        error_record: *mut *mut u16,
    ) -> i32;

}

#[link(name = "ole32")]
unsafe extern "system" {
    /// Release a buffer allocated by HNS (the `ErrorRecord` returned
    /// from any `HcnCreate*` / `HcnDelete*` call). Mirrors the
    /// `CoTaskMemFree` semantics callers of `CoTaskMemAlloc` rely on;
    /// HNS documents that the `ErrorRecord` is `CoTaskMemAlloc`-backed.
    pub fn CoTaskMemFree(ptr: *const c_void);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that every imported HCN symbol is
    /// resolvable. The test is `#[ignore]`-free and doesn't actually
    /// *call* any of the functions (creating a real HNS network would
    /// require Hyper-V admin privileges and leave state behind) — it
    /// just takes the function pointer address, which forces the
    /// linker to resolve the symbol out of `computenetwork.dll`. This
    /// is the completion-metric gate for Task I-1.
    ///
    /// On a non-Windows target this test compiles to nothing because
    /// the whole `hns` module is gated by `cfg(windows)` at the
    /// parent-module declaration site.
    #[test]
    fn hcn_symbols_link() {
        let _create_net: unsafe extern "system" fn(
            *const Guid,
            *const u16,
            *mut HCN_NETWORK,
            *mut *mut u16,
        ) -> i32 = HcnCreateNetwork;
        let _close_net: unsafe extern "system" fn(HCN_NETWORK) -> i32 = HcnCloseNetwork;
        let _enumerate_nets: unsafe extern "system" fn(
            *const u16,
            *mut *mut u16,
            *mut *mut u16,
        ) -> i32 = HcnEnumerateNetworks;
        let _open_net: unsafe extern "system" fn(
            *const Guid,
            *mut HCN_NETWORK,
            *mut *mut u16,
        ) -> i32 = HcnOpenNetwork;
        let _query_net: unsafe extern "system" fn(
            HCN_NETWORK,
            *const u16,
            *mut *mut u16,
            *mut *mut u16,
        ) -> i32 = HcnQueryNetworkProperties;
        let _delete_net: unsafe extern "system" fn(*const Guid, *mut *mut u16) -> i32 =
            HcnDeleteNetwork;
        let _create_ep: unsafe extern "system" fn(
            HCN_NETWORK,
            *mut Guid,
            *const u16,
            *mut HCN_ENDPOINT,
            *mut *mut u16,
        ) -> i32 = HcnCreateEndpoint;
        let _close_ep: unsafe extern "system" fn(HCN_ENDPOINT) -> i32 = HcnCloseEndpoint;
        let _enumerate_eps: unsafe extern "system" fn(
            *const u16,
            *mut *mut u16,
            *mut *mut u16,
        ) -> i32 = HcnEnumerateEndpoints;
        let _open_ep: unsafe extern "system" fn(
            *const Guid,
            *mut HCN_ENDPOINT,
            *mut *mut u16,
        ) -> i32 = HcnOpenEndpoint;
        let _delete_ep: unsafe extern "system" fn(*const Guid, *mut *mut u16) -> i32 =
            HcnDeleteEndpoint;
        let _query_ep: unsafe extern "system" fn(
            HCN_ENDPOINT,
            *const u16,
            *mut *mut u16,
            *mut *mut u16,
        ) -> i32 = HcnQueryEndpointProperties;
        let _co_task_mem_free: unsafe extern "system" fn(*const c_void) = CoTaskMemFree;
    }

    #[test]
    fn nat_network_json_matches_hcn_v2_golden_shape() {
        let json = serde_json::to_string(&build_network_settings(
            "jyth-nat-demo".to_owned(),
            &vm_model::network::Nat::default(),
        ))
        .expect("network DTO must serialize");

        assert_eq!(
            json,
            r#"{"SchemaVersion":{"Major":2,"Minor":0},"Name":"jyth-nat-demo","Type":"NAT","MacPool":{"Ranges":[{"StartMacAddress":"00-15-5D-76-00-00","EndMacAddress":"00-15-5D-76-00-FF"}]},"Ipams":[{"Type":"Static","Subnets":[{"IpAddressPrefix":"10.77.0.0/24","Routes":[{"NextHop":"10.77.0.1","DestinationPrefix":"0.0.0.0/0"}]}]}]}"#
        );
    }

    #[test]
    fn endpoint_json_matches_hcn_v2_golden_shape() {
        let network_id = Guid::from_uuid(
            &uuid::Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").expect("valid UUID"),
        );
        let json = serde_json::to_string(&build_endpoint_settings(
            "jyth-ep-demo".to_owned(),
            &network_id,
            &vm_model::network::Nat::default(),
        ))
        .expect("endpoint DTO must serialize");

        assert_eq!(
            json,
            r#"{"SchemaVersion":{"Major":2,"Minor":0},"Name":"jyth-ep-demo","HostComputeNetwork":"00112233-4455-6677-8899-aabbccddeeff","IpConfigurations":[{"IpAddress":"10.77.0.10","PrefixLength":24}],"Dns":{"ServerList":["8.8.8.8","1.1.1.1"]}}"#
        );
    }

    #[test]
    fn name_query_escapes_json_special_characters() {
        let json = serde_json::to_string(&NameQuery {
            name: r#"jyth-"nat"\candidate"#.to_owned(),
        })
        .expect("name query must serialize");

        assert_eq!(json, r#"{"Name":"jyth-\"nat\"\\candidate"}"#);
    }

    #[test]
    fn resource_properties_accept_id_aliases() {
        let endpoint_id = "00112233-4455-6677-8899-aabbccddeeff";
        for document in [
            format!(r#"{{"ID":"{{{endpoint_id}}}","Name":"endpoint"}}"#),
            format!(r#"{{"Id":"{endpoint_id}","Name":"endpoint"}}"#),
        ] {
            assert_eq!(
                parse_endpoint_id_from_props(&document).expect("typed ID must parse"),
                Guid::from_uuid(&uuid::Uuid::parse_str(endpoint_id).expect("valid reference UUID"))
            );
            assert_eq!(
                property_name(&document, "endpoint").expect("typed properties must parse"),
                Some("endpoint".to_owned())
            );
        }
    }

    #[test]
    fn enumerated_hns_ids_accept_string_and_object_forms() {
        let expected =
            uuid::Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").expect("valid UUID");
        let string_form =
            parse_enumerated_ids(r#"["{00112233-4455-6677-8899-aabbccddeeff}"]"#, "Networks")
                .expect("parse string enumeration");
        assert_eq!(string_form, vec![Guid::from_uuid(&expected)]);

        let object_form = parse_enumerated_ids(
            r#"{"Networks":[{"ID":"00112233-4455-6677-8899-aabbccddeeff"}]}"#,
            "Networks",
        )
        .expect("parse object enumeration");
        assert_eq!(object_form, vec![Guid::from_uuid(&expected)]);
    }

    #[test]
    fn malformed_enumerated_hns_id_fails_closed() {
        let result = parse_enumerated_ids(r#"["not-a-guid"]"#, "Endpoints");
        assert!(result.is_err());
    }

    /// Layout sanity: the `Guid` we hand to HNS through `*const Guid`
    /// must be 16 bytes — `windows-sys`'s `GUID` is the same size and
    /// HNS expects exactly a `REFGUID`. A non-16-byte struct would
    /// silently mis-cast and HNS would reject the call with a schema
    /// error before it ever read the GUID.
    #[test]
    fn guid_is_16_bytes() {
        assert_eq!(std::mem::size_of::<Guid>(), 16);
    }

    /// `Guid::from_uuid` round-trips a fixed reference UUID through the
    /// 4-field layout Windows expects. The values are taken from the
    /// RFC 4122 example `00112233-4455-6677-8899-aabbccddeeff` so the
    /// bytes are unambiguous and easy to spot if a regression ever
    /// swaps the layouts.
    #[test]
    fn from_uuid_yields_windows_layout() {
        let u = uuid::Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").expect("valid uuid");
        let g = Guid::from_uuid(&u);
        assert_eq!(g.data1, 0x00112233);
        assert_eq!(g.data2, 0x4455);
        assert_eq!(g.data3, 0x6677);
        assert_eq!(g.data4, [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    /// Regression guard for the bug surfaced by `cargo run -p
    /// net-probe --release`: `EndpointId` must be emitted in the
    /// un-braced, lowercase form HCS resolves against the HNS
    /// endpoint table (`go-winio/pkg/guid.GUID.String()` shape,
    /// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). The earlier code here
    /// formatted the GUID braced-uppercase, which HCS couldn't
    /// match against an HNS endpoint and so rejected the whole VM
    /// at `HcsCreateComputeSystem` time with
    /// `HCS_E_SYSTEM_INVALID_CONFIGURATION` (HRESULT 0x8037010D,
    /// `OperationFailure.Detail: Construct`).
    #[test]
    fn endpoint_id_string_is_unbraced_lowercase() {
        let u = uuid::Uuid::parse_str("019f6828-9125-7261-8ad4-11e2402516f1").expect("valid uuid");
        let g = Guid::from_uuid(&u);
        assert_eq!(
            format_endpoint_id_string(&g),
            "019f6828-9125-7261-8ad4-11e2402516f1",
        );
    }

    /// The `EndpointId` string must NOT carry surrounding `{}` braces.
    /// Braced values surface as `HCS_E_SYSTEM_INVALID_CONFIGURATION`
    /// at `HcsCreateComputeSystem`. Drives the exact symptom in
    /// `net-probe` even when case + digits are otherwise correct
    /// (HCS's endpoint resolver treats the braces as part of the
    /// string key).
    #[test]
    fn endpoint_id_string_has_no_braces() {
        let u = uuid::Uuid::parse_str("019f6828-9125-7261-8ad4-11e2402516f1").expect("valid uuid");
        let s = format_endpoint_id_string(&Guid::from_uuid(&u));
        assert!(!s.starts_with('{'));
        assert!(!s.ends_with('}'));
        assert_eq!(s.len(), 36, "expected 36-char GUID, got {s}");
    }

    /// The `EndpointId` string must be lowercase. HCS's resolver
    /// does a case-sensitive compare against the GUID strings HNS
    /// exposes (which HNS emits lowercase), so an uppercase
    /// `019F6828-...` would fail to resolve with the same
    /// `0x8037010D / Construct` error.
    #[test]
    fn endpoint_id_string_is_lowercase() {
        let u = uuid::Uuid::parse_str("019f6828-9125-7261-8ad4-11e2402516f1").expect("valid uuid");
        let s = format_endpoint_id_string(&Guid::from_uuid(&u));
        assert_eq!(s, s.to_lowercase());
    }

    #[test]
    fn malformed_journal_guid_falls_back_to_name_based_deletion() {
        let valid = "11223344-5566-7788-99aa-bbccddeeff00";
        let braced = "{11223344-5566-7788-99aa-bbccddeeff00}";
        assert!(matches!(
            classify_journal_id(Some(valid)),
            Some(JournalId::Exact(_))
        ));
        assert!(matches!(
            classify_journal_id(Some(braced)),
            Some(JournalId::Exact(_))
        ));
        assert!(matches!(
            classify_journal_id(Some("not-a-guid")),
            Some(JournalId::Malformed)
        ));
        assert!(matches!(
            classify_journal_id(Some("11223344-5566-7788-99aa-bbccddeeff0Z")),
            Some(JournalId::Malformed)
        ));
        assert_eq!(
            classify_journal_id(None),
            None,
            "an absent journaled ID takes the name-based path"
        );
    }

    #[test]
    fn hns_absence_classification_relies_on_the_hresult_whitelist_only() {
        assert!(hns_absent(0x8007_0490u32 as i32, ""));
        assert!(hns_absent(0x8007_0002u32 as i32, ""));
        assert!(
            !hns_absent(-1, "The specified resource was not found."),
            "localized error text must not classify absence"
        );
        assert!(!hns_absent(-1, ""));
        assert!(!hns_absent(0x8007_0005u32 as i32, ""));
    }
}

use crate::core::ToWide;
use crate::error::HcsError;
use error_stack::Report;
use serde::{Deserialize, Serialize};

/// HCN schema versions are objects rather than strings. Keeping the version
/// as a DTO field prevents every HNS document from hand-building the same
/// JSON fragment and makes the wire contract visible in golden tests.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SchemaVersion {
    major: u32,
    minor: u32,
}

impl SchemaVersion {
    const fn v2() -> Self {
        Self { major: 2, minor: 0 }
    }
}

#[derive(Debug, Serialize)]
enum NetworkType {
    #[serde(rename = "NAT")]
    Nat,
}

#[derive(Debug, Serialize)]
enum IpamType {
    #[serde(rename = "Static")]
    Static,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct MacPool {
    ranges: Vec<MacRange>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct MacRange {
    start_mac_address: String,
    end_mac_address: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkSettings {
    schema_version: SchemaVersion,
    name: String,
    #[serde(rename = "Type")]
    network_type: NetworkType,
    mac_pool: MacPool,
    ipams: Vec<IpamSettings>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct IpamSettings {
    #[serde(rename = "Type")]
    ipam_type: IpamType,
    subnets: Vec<SubnetSettings>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SubnetSettings {
    ip_address_prefix: String,
    routes: Vec<RouteSettings>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct RouteSettings {
    next_hop: String,
    destination_prefix: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct EndpointSettings {
    schema_version: SchemaVersion,
    name: String,
    host_compute_network: String,
    ip_configurations: Vec<IpConfiguration>,
    dns: DnsSettings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct IpConfiguration {
    ip_address: String,
    prefix_length: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DnsSettings {
    server_list: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct NameQuery {
    name: String,
}

#[derive(Debug, Serialize)]
struct EmptyQuery {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct PropertiesQuery {
    schema_version: SchemaVersion,
    flags: u32,
}

/// HNS property documents use `ID` on current Windows builds and `Id` on
/// older builds. Serde aliases keep that compatibility policy in one typed
/// response DTO instead of scattering field scans through the cleanup path.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResourceProperties {
    #[serde(rename = "ID", alias = "Id", default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EnumerationDocument {
    List(Vec<EnumerationEntry>),
    Collections(EnumerationCollections),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EnumerationEntry {
    String(String),
    Object(EnumerationObject),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EnumerationObject {
    #[serde(rename = "ID", alias = "Id", default)]
    id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EnumerationCollections {
    #[serde(default)]
    networks: Option<Vec<EnumerationEntry>>,
    #[serde(default)]
    endpoints: Option<Vec<EnumerationEntry>>,
}

fn build_network_settings(network_name: String, nat: &vm_model::network::Nat) -> NetworkSettings {
    NetworkSettings {
        schema_version: SchemaVersion::v2(),
        name: network_name,
        network_type: NetworkType::Nat,
        mac_pool: MacPool {
            ranges: vec![MacRange {
                start_mac_address: "00-15-5D-76-00-00".to_owned(),
                end_mac_address: "00-15-5D-76-00-FF".to_owned(),
            }],
        },
        ipams: vec![IpamSettings {
            ipam_type: IpamType::Static,
            subnets: vec![SubnetSettings {
                ip_address_prefix: nat.subnet().to_string(),
                routes: vec![RouteSettings {
                    next_hop: nat.gateway().to_string(),
                    destination_prefix: "0.0.0.0/0".to_owned(),
                }],
            }],
        }],
    }
}

fn build_endpoint_settings(
    endpoint_name: String,
    network_id: &Guid,
    nat: &vm_model::network::Nat,
) -> EndpointSettings {
    EndpointSettings {
        schema_version: SchemaVersion::v2(),
        name: endpoint_name,
        host_compute_network: format_endpoint_id_string(network_id),
        ip_configurations: vec![IpConfiguration {
            ip_address: nat.guest_ip().to_string(),
            prefix_length: nat.subnet().prefix_len(),
        }],
        dns: DnsSettings {
            server_list: nat.dns().iter().map(ToString::to_string).collect(),
        },
    }
}

fn serialize_hns_json<T: Serialize>(
    document: &T,
    context: &str,
) -> Result<crate::core::WideString, Report<HcsError>> {
    serde_json::to_string(document)
        .map(|json| json.to_wide())
        .map_err(|error| {
            Report::new(HcsError::Serialize).attach(format!("serialize HNS {context}: {error}"))
        })
}

/// Result of [`create_network_and_endpoint_with_callbacks`]. The handles are owned by
/// the caller; `Drop` is *not* implemented (the type would be too easy
/// to `mem::forget` across the FFI boundary) — instead the `Vm` that
/// holds this struct's fields calls [`close_and_delete_result`] explicitly in
/// its own `Drop` so the delete-on-drop ordering is visible at every
/// step. The raw pointer fields are stored wrapped in `Option`, mirroring
/// the way the `Vm` already manages its HCS handle behind a
/// `Mutex<Option<ComputeSystem>>`.
pub(crate) struct NetworkState {
    /// GUID that identifies the HNS network to HNS. Used for the
    /// `HcnDeleteNetwork` call in [`close_and_delete_result`] — the network's
    /// `Name` (inside the settings JSON) is **not** the lookup key, the
    /// GUID is.
    pub network_id: Guid,
    /// GUID that identifies the HNS endpoint. Also re-used as the
    /// `endpoint_id` string the host serialises into the HCS
    /// `NetworkAdapters[].EndpointId` field (v2 flat string, not the
    /// v1 nested `Endpoint.Id` form) — HCS resolves the NIC via
    /// that GUID string at VM start, so the same identifier has to be
    /// carried into the HCS configuration.
    pub endpoint_id: Guid,
    /// `endpoint_id` formatted as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    /// (lowercase, un-braced) — the string form HCS expects in the
    /// `Devices.NetworkAdapters[].EndpointId` field. (`hcsschema.v2`
    /// declares `EndpointId` as a plain `string`; hcsshim populates it
    /// via `go-winio`'s `guid.GUID.String()`, which emits exactly this
    /// lowercase un-braced form. Braced or uppercase values are
    /// rejected by HCS's endpoint-resolution step at
    /// `HcsCreateComputeSystem` time.) Pre-formatted at create time
    /// so the HCS serialisation path doesn't have to know about GUID
    /// formatting.
    pub endpoint_id_string: String,
    pub endpoint_handle: HCN_ENDPOINT,
    pub network_handle: HCN_NETWORK,
}

// SAFETY: the raw HNS handles are kernel-owned opaque pointers (the
// HNS service actually owns the underlying objects across process
// boundaries; our handles are just opaque refs that get invalidated
// by `HcnClose*`). They pose no aliasing hazard at the Rust level as
// long as all access to them is serialised — `Vm::drop` is the only
// place that reads/writes them, and that path is gated by the
// `network: Mutex<Option<NetworkState>>` field on `Vm`. So `Send` is
// safe (moving ownership across threads doesn't touch the kernel
// state) and `Sync` is safe (concurrent access is impossible behind
// the `Mutex`). The `IVm: Send + Sync` bound would otherwise reject
// `*mut c_void` fields even though they never escape their `Mutex`.
unsafe impl Send for NetworkState {}
unsafe impl Sync for NetworkState {}

/// One-shot helper that:
///   1. Creates the HNS NAT network identified by a fresh GUID
///      (named `jyth-nat-<vm_id>` in the JSON, but the GUID is the
///      identifier HNS uses) with the CIDR/gateway from [`Nat`].
///   2. Creates the HNS endpoint identified by another fresh GUID
///      (named `jyth-ep-<vm_id>`), with the static guest IP + DNS,
///      `Attach: true` so HNS hot-attaches to the VM the second we issue
///      a `HcsStartComputeSystem` call (HCS resolves the NIC via the
///      endpoint GUID we put in the JSON).
///
/// The handles returned are *owned* — the caller must close + delete
/// them. Use [`close_and_delete_result`] for that, ideally called from
/// `Vm::drop` *after* the HCS compute system is removed (so the VM has
/// already released its grip on the endpoint before we delete it).
/// Create the network and endpoint while allowing the caller to persist each
/// observed HNS identity before the next external side effect. The callbacks
/// run after the corresponding HCN call has succeeded and before the next
/// HCN call begins.
pub(crate) fn create_network_and_endpoint_with_callbacks<NetworkCallback, EndpointCallback>(
    vm_id: uuid::Uuid,
    network_id_uuid: uuid::Uuid,
    nat: &vm_model::network::Nat,
    on_network_created: NetworkCallback,
    on_endpoint_created: EndpointCallback,
) -> Result<NetworkState, Report<HcsError>>
where
    NetworkCallback: FnOnce(&str) -> Result<(), Report<HcsError>>,
    EndpointCallback: FnOnce(&str) -> Result<(), Report<HcsError>>,
{
    let network_name = format!("jyth-nat-{vm_id}");
    let endpoint_name = format!("jyth-ep-{vm_id}");

    // `network_id` is the HNS identifier HNS itself keys the network
    // by (`HcnDeleteNetwork` uses this GUID, not the JSON `Name`).
    // `endpoint_id` is a placeholder passed (by mutable ref) to
    // `HcnCreateEndpoint` — but HNS is free to ignore a non-zero
    // caller-supplied endpoint GUID and allocate its own. So we always
    // query the endpoint back via `HcnQueryEndpointProperties` after
    // the create succeeds and use the HNS-allocated GUID for both the
    // `HcnDeleteEndpoint` later and the HCS
    // `NetworkAdapters[].EndpointId` field. This mirrors hcsshim's
    // `createEndpoint` (pass `guid.GUID{}`, query back, use `endpoint.Id`).
    let network_id = Guid::from_uuid(&network_id_uuid);
    // Zero-init: matches the hcsshim pattern and asks HNS to allocate.
    let endpoint_seed_id = Guid::from_uuid(&uuid::Uuid::nil());

    // The HCN v2 NAT and endpoint documents are private DTOs. Serde owns all
    // quoting and escaping; the only raw JSON that reaches the FFI boundary
    // is the UTF-16 payload returned by `serialize_hns_json`.
    let network_settings = build_network_settings(network_name.clone(), nat);
    let wide_settings = serialize_hns_json(&network_settings, "network settings")?;
    let endpoint_settings = build_endpoint_settings(endpoint_name.clone(), &network_id, nat);
    let wide_ep_settings = serialize_hns_json(&endpoint_settings, "endpoint settings")?;

    let mut network_handle: HCN_NETWORK = std::ptr::null_mut();
    let mut network_error: *mut u16 = std::ptr::null_mut();
    let hres = unsafe {
        HcnCreateNetwork(
            &network_id,
            wide_settings.as_ptr(),
            &mut network_handle,
            &mut network_error,
        )
    };
    if hres != S_OK || network_handle.is_null() {
        let diag = take_hns_error(network_error);
        rollback_network_creation(&network_id, None, std::ptr::null_mut(), network_handle);
        let diag_suffix = if diag.is_empty() {
            String::new()
        } else {
            format!(": HNS error document: {diag}")
        };
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnCreateNetwork(name={network_name}) failed: HRESULT 0x{hres:08X}{diag_suffix}",
        )));
    }

    let network_id_string = format_endpoint_id_string(&network_id);
    if let Err(error) = on_network_created(&network_id_string) {
        rollback_network_creation(&network_id, None, std::ptr::null_mut(), network_handle);
        return Err(error);
    }

    // HNS allocates the endpoint GUID into `endpoint_id_out` when the
    // caller passes zero-init; hcsshim uses that pattern then queries
    // the endpoint back to learn the real GUID. We do the same here.
    // HNS does NOT honor a caller-supplied non-zero GUID for the
    // endpoint — `endpoint_seed_id` is always zero so HNS picks the
    // GUID, and we then read it back out of
    // `HcnQueryEndpointProperties`'s JSON `ID` field below.
    let mut endpoint_id_out = endpoint_seed_id;
    let mut endpoint_handle: HCN_ENDPOINT = std::ptr::null_mut();
    let mut endpoint_error: *mut u16 = std::ptr::null_mut();
    let hres = unsafe {
        HcnCreateEndpoint(
            network_handle,
            &mut endpoint_id_out,
            wide_ep_settings.as_ptr(),
            &mut endpoint_handle,
            &mut endpoint_error,
        )
    };
    if hres != S_OK || endpoint_handle.is_null() {
        let diag = take_hns_error(endpoint_error);
        let endpoint_id_for_rollback = (!endpoint_handle.is_null()).then_some(&endpoint_id_out);
        rollback_network_creation(
            &network_id,
            endpoint_id_for_rollback,
            endpoint_handle,
            network_handle,
        );
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnCreateEndpoint({endpoint_name}) on {network_name} failed: HRESULT \
             0x{hres:08X}{}",
            if diag.is_empty() {
                String::new()
            } else {
                format!(": HNS error document: {diag}")
            },
        )));
    }

    // The HNS-allocated endpoint GUID lives in the `ID` field of the
    // JSON document returned by `HcnQueryEndpointProperties`. HCS
    // resolves the VM NIC at start time by looking up the endpoint
    // referenced in `Devices.NetworkAdapters[].EndpointId`, so we have
    // to put the real (HNS-allocated) GUID into that field — putting
    // the pre-populated zero GUID there surfaces as
    // `HCS_E_SYSTEM_INVALID_CONFIGURATION` (HRESULT 0x8037010D,
    // `OperationFailure.Detail: Construct`) at `HcsCreateComputeSystem`
    // time, because HCS simply fails to resolve a matching endpoint.
    //
    // The empty `HostComputeQuery` (SchemaVersion v2.0, no flags) is
    // the same one hcsshim's `defaultQuery()` produces; it returns the
    // standard properties which include `ID` as a GUID string. HNS
    // emits it braced (e.g. `"{019f6828-9125-7261-8ad4-11c09fa1c890}"`)
    // but the brace handling is incidental —
    // [`parse_endpoint_id_from_props`] strips the braces before
    // parsing. We parse the GUID back into a `Guid` so we can
    // re-format it via [`format_endpoint_id_string`] into the
    // un-braced lowercase form HCS expects (HCS does a case-sensitive
    // compare against the GUID strings HNS exposes in lowercase, so
    // matching HNS's exact case keeps resolution happy).
    let wide_query = properties_query()?;
    let mut ep_props: *mut u16 = std::ptr::null_mut();
    let mut ep_query_err: *mut u16 = std::ptr::null_mut();
    let hres = unsafe {
        HcnQueryEndpointProperties(
            endpoint_handle,
            wide_query.as_ptr(),
            &mut ep_props,
            &mut ep_query_err,
        )
    };
    if hres != S_OK {
        let diag = take_hns_error(ep_query_err);
        let _ = take_hns_error(ep_props);
        rollback_network_creation(
            &network_id,
            Some(&endpoint_id_out),
            endpoint_handle,
            network_handle,
        );
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnQueryEndpointProperties({endpoint_name}) failed: HRESULT 0x{hres:08X}{}",
            if diag.is_empty() {
                String::new()
            } else {
                format!(": HNS error document: {diag}")
            },
        )));
    }
    let props_json = take_hns_error(ep_props);
    if props_json.is_empty() {
        // We can't safely proceed without the real endpoint GUID.
        rollback_network_creation(
            &network_id,
            Some(&endpoint_id_out),
            endpoint_handle,
            network_handle,
        );
        return Err(Report::new(HcsError::Network)
            .attach("HcnQueryEndpointProperties returned an empty properties document"));
    }

    // Parse the JSON `{"ID":"{guid}",...}` document HNS returned.
    // We deliberately accept either braced (HNS's observed form) or
    // un-braced GUID strings so a future HNS schema tweak can't break
    // us; both forms parse via guid_from_string below.
    let endpoint_id = match parse_endpoint_id_from_props(&props_json) {
        Ok(g) => g,
        Err(parse_err) => {
            rollback_network_creation(
                &network_id,
                Some(&endpoint_id_out),
                endpoint_handle,
                network_handle,
            );
            return Err(Report::new(HcsError::Network)
                .attach(parse_err)
                .attach(format!("HNS endpoint props JSON: {props_json}")));
        }
    };

    // Format the HNS-allocated endpoint GUID as the *un-braced*
    // lowercase hyphenated form HCS's `NetworkAdapters[].EndpointId`
    // field expects. hcsshim's `hcsschema.NetworkAdapter.EndpointId` is
    // a plain `string`, and every place hcsshim populates it uses
    // `go-winio`'s `guid.GUID.String()` which emits exactly the
    // `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` lowercase, un-braced
    // form (https://github.com/microsoft/go-winio/blob/main/pkg/guid/guid.go).
    //
    // Earlier code here emitted a braced uppercase form
    // (`{XXXXXXXX-...}`), which HCS does not match against the HNS
    // endpoint table — `HcsCreateComputeSystem` then fails at the
    // `Construct` step with `HCS_E_SYSTEM_INVALID_CONFIGURATION`
    // (HRESULT 0x8037010D, `OperationFailure.Detail: Construct`),
    // exactly the symptom the net-probe example was hitting. Same
    // string shape hcsshim writes keeps resolution happy. Case is
    // also significant here: HCS does a case-sensitive compare of
    // the `EndpointId` string against the GUID strings HNS exposes,
    // and HNS emits lowercase, so lowercase matches. Uppercase does
    // not, and bracing the GUID is straight up rejected on the same
    // compare path.
    let endpoint_id_string = format_endpoint_id_string(&endpoint_id);

    if let Err(error) = on_endpoint_created(&endpoint_id_string) {
        rollback_network_creation(
            &network_id,
            Some(&endpoint_id_out),
            endpoint_handle,
            network_handle,
        );
        return Err(error);
    }

    Ok(NetworkState {
        network_id,
        endpoint_id,
        endpoint_id_string,
        endpoint_handle,
        network_handle,
    })
}

/// Format the HNS-allocated endpoint [`Guid`] as the string HCS's
/// `Devices.NetworkAdapters[].EndpointId` field expects. See
/// [`NetworkState::endpoint_id_string`] for the rationale — in
/// short, HCS does a case-sensitive compare of this string against
/// the GUID strings HNS exposes, and accepts only the un-braced
/// lowercase `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` form (matching
/// `go-winio/pkg/guid.GUID.String()` and hcsshim's `NetworkAdapter`
/// serialisation). Braced or uppercase variants are rejected with
/// `HCS_E_SYSTEM_INVALID_CONFIGURATION` (`0x8037010D`,
/// `OperationFailure.Detail: Construct`) at
/// `HcsCreateComputeSystem` time, when HCS can't resolve the NIC.
///
/// Extracted from [`create_network_and_endpoint_with_callbacks`] so the format can
/// be unit-tested in isolation.
fn format_endpoint_id_string(g: &Guid) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

/// Parse the `ID` field out of an `HcnQueryEndpointProperties` JSON
/// document and return the corresponding [`Guid`]. Accepts either
/// braced (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`) or un-braced GUID
/// strings, in either lowercase or uppercase hex.
///
/// The response is deserialized into the internal HNS property DTO so JSON
/// quoting and field boundaries are handled by Serde rather than by a string
/// scan. The returned `String` error remains small enough to attach directly
/// to the network operation report.
fn parse_endpoint_id_from_props(props_json: &str) -> Result<Guid, String> {
    let properties: ResourceProperties = serde_json::from_str(props_json)
        .map_err(|error| format!("endpoint properties JSON is invalid: {error}"))?;
    let raw_guid = properties
        .id
        .ok_or_else(|| "endpoint properties JSON has no `ID`/`Id` field".to_owned())?;

    // Strip optional surrounding braces: HNS returns the GUID braced.
    let stripped = raw_guid
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(&raw_guid);
    parse_guid_string(stripped)
        .ok_or_else(|| format!("malformed endpoint GUID string `{raw_guid}`"))
}

/// Parse a 36-char `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` GUID string
/// (case-insensitive) into a [`Guid`]. Returns `None` on any
/// structural deviation from the standard RFC-4122 hyphenated layout.
fn parse_guid_string(s: &str) -> Option<Guid> {
    if s.len() != 36 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return None;
    }
    let parse_hex_u32 = |b: &[u8]| -> Option<u32> {
        let mut v = 0u32;
        for &c in b {
            let d = (c as char).to_digit(16)?;
            v = v.checked_shl(4)? | d;
        }
        Some(v)
    };
    let parse_hex_u16 = |b: &[u8]| -> Option<u16> {
        let mut v = 0u16;
        for &c in b {
            let d = (c as char).to_digit(16)? as u16;
            v = v.checked_shl(4)? | d;
        }
        Some(v)
    };
    let parse_hex_u8 = |b: &[u8]| -> Option<u8> {
        let mut v = 0u8;
        for &c in b {
            let d = (c as char).to_digit(16)? as u8;
            v = v.checked_shl(4)? | d;
        }
        Some(v)
    };
    let data1 = parse_hex_u32(&bytes[0..8])?;
    let data2 = parse_hex_u16(&bytes[9..13])?;
    let data3 = parse_hex_u16(&bytes[14..18])?;
    let data4_byte0 = parse_hex_u8(&bytes[19..21])?;
    let data4_byte1 = parse_hex_u8(&bytes[21..23])?;
    // Last 12 hex chars (no internal dashes): bytes[24..36].
    let last = &bytes[24..36];
    let mut data4 = [0u8; 8];
    data4[0] = data4_byte0;
    data4[1] = data4_byte1;
    for i in 0..6 {
        data4[2 + i] = parse_hex_u8(&last[i * 2..i * 2 + 2])?;
    }
    Some(Guid {
        data1,
        data2,
        data3,
        data4,
    })
}

/// Take ownership of the HNS `ErrorRecord` buffer (allocated with
/// `CoTaskMemAlloc`), copy its UTF-16 contents into a Rust `String`,
/// and release the buffer. Returns the empty string when `ptr` is null
/// (HNS leaves it null on successes and on a few failure paths where no
/// detail document was produced).
///
/// The buffer scan is capped at [`crate::core::MAX_WIDE_STRING_UNITS`];
/// an unterminated buffer (corrupt HNS state) is truncated at the cap
/// instead of being read out of bounds. The diagnostic is display-only —
/// absence classification no longer reads it — so truncation is safe.
fn take_hns_error(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: HNS documents that `ErrorRecord` is `CoTaskMemAlloc`-backed
    // and null-terminated. The capped scan bounds the read; we free with
    // `CoTaskMemFree` at the end.
    let len =
        unsafe { crate::core::wide_strlen(ptr) }.unwrap_or(crate::core::MAX_WIDE_STRING_UNITS);
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let s = String::from_utf16_lossy(slice);
    unsafe { CoTaskMemFree(ptr as *const c_void) };
    s
}

fn exact_name_query(name: &str) -> Result<crate::core::WideString, Report<HcsError>> {
    serialize_hns_json(
        &NameQuery {
            name: name.to_owned(),
        },
        "name query",
    )
}

fn empty_hns_query() -> Result<crate::core::WideString, Report<HcsError>> {
    serialize_hns_json(&EmptyQuery {}, "empty query")
}

fn properties_query() -> Result<crate::core::WideString, Report<HcsError>> {
    serialize_hns_json(
        &PropertiesQuery {
            schema_version: SchemaVersion::v2(),
            flags: 0,
        },
        "properties query",
    )
}

fn parse_enumerated_ids(document: &str, collection: &str) -> Result<Vec<Guid>, Report<HcsError>> {
    if document.trim().is_empty() {
        return Ok(Vec::new());
    }
    let document: EnumerationDocument = serde_json::from_str(document).map_err(|error| {
        Report::new(HcsError::Network)
            .attach(format!("parse HNS {collection} enumeration: {error}"))
    })?;

    let values = match document {
        EnumerationDocument::List(values) => values,
        EnumerationDocument::Collections(collections) => match collection {
            "Networks" => collections.networks.unwrap_or_default(),
            "Endpoints" => collections.endpoints.unwrap_or_default(),
            _ => {
                return Err(Report::new(HcsError::Network).attach(format!(
                    "unsupported HNS enumeration collection `{collection}`"
                )));
            }
        },
    };

    values
        .into_iter()
        .map(|value| {
            let raw = match value {
                EnumerationEntry::String(raw) => raw,
                EnumerationEntry::Object(object) => object.id.ok_or_else(|| {
                    Report::new(HcsError::Network)
                        .attach(format!("HNS {collection} enumeration entry has no GUID"))
                })?,
            };
            let unbraced = raw
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
                .unwrap_or(&raw);
            parse_guid_string(unbraced).ok_or_else(|| {
                Report::new(HcsError::Network).attach(format!(
                    "HNS {collection} enumeration contains malformed GUID `{raw}`"
                ))
            })
        })
        .collect()
}

fn property_name(document: &str, resource: &str) -> Result<Option<String>, Report<HcsError>> {
    let properties: ResourceProperties = serde_json::from_str(document).map_err(|error| {
        Report::new(HcsError::Network).attach(format!("parse HNS {resource} properties: {error}"))
    })?;
    Ok(properties.name)
}

fn network_name_for_id(id: &Guid) -> Result<Option<String>, Report<HcsError>> {
    // Build the query document BEFORE opening the handle: if serialization
    // fails here, no handle exists yet and nothing leaks.
    let query = empty_hns_query()?;
    let mut handle: HCN_NETWORK = std::ptr::null_mut();
    let mut error_record = std::ptr::null_mut();
    let hres = unsafe { HcnOpenNetwork(id, &mut handle, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres != S_OK || handle.is_null() {
        if hns_absent(hres, &diagnostic) {
            return Ok(None);
        }
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnOpenNetwork failed: HRESULT 0x{hres:08X}; {diagnostic}"
        )));
    }

    let mut properties = std::ptr::null_mut();
    let mut query_error = std::ptr::null_mut();
    let hres = unsafe {
        HcnQueryNetworkProperties(handle, query.as_ptr(), &mut properties, &mut query_error)
    };
    let properties_json = take_hns_error(properties);
    let query_diagnostic = take_hns_error(query_error);
    let close_result = unsafe { HcnCloseNetwork(handle) };
    if hres != S_OK {
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnQueryNetworkProperties failed: HRESULT 0x{hres:08X}; {query_diagnostic}"
        )));
    }
    if close_result != S_OK {
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnCloseNetwork failed while checking a recovery candidate: HRESULT 0x{close_result:08X}"
        )));
    }
    property_name(&properties_json, "network")
}

fn endpoint_name_for_id(id: &Guid) -> Result<Option<String>, Report<HcsError>> {
    // Query-first, same as `network_name_for_id`: a serialization failure
    // happens before any handle exists, so it cannot leak one.
    let query = empty_hns_query()?;
    let mut handle: HCN_ENDPOINT = std::ptr::null_mut();
    let mut error_record = std::ptr::null_mut();
    let hres = unsafe { HcnOpenEndpoint(id, &mut handle, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres != S_OK || handle.is_null() {
        if hns_absent(hres, &diagnostic) {
            return Ok(None);
        }
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnOpenEndpoint failed: HRESULT 0x{hres:08X}; {diagnostic}"
        )));
    }

    let mut properties = std::ptr::null_mut();
    let mut query_error = std::ptr::null_mut();
    let hres = unsafe {
        HcnQueryEndpointProperties(handle, query.as_ptr(), &mut properties, &mut query_error)
    };
    let properties_json = take_hns_error(properties);
    let query_diagnostic = take_hns_error(query_error);
    let close_result = unsafe { HcnCloseEndpoint(handle) };
    if hres != S_OK {
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnQueryEndpointProperties failed: HRESULT 0x{hres:08X}; {query_diagnostic}"
        )));
    }
    if close_result != S_OK {
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnCloseEndpoint failed while checking a recovery candidate: HRESULT 0x{close_result:08X}"
        )));
    }
    property_name(&properties_json, "endpoint")
}

fn find_network_id_by_name(name: &str) -> Result<Option<Guid>, Report<HcsError>> {
    let query = exact_name_query(name)?;
    let mut networks = std::ptr::null_mut();
    let mut error_record = std::ptr::null_mut();
    let hres = unsafe { HcnEnumerateNetworks(query.as_ptr(), &mut networks, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres != S_OK {
        // An absent network surfaces as a not-found enumeration error; that
        // is the same idempotent "already gone" outcome as an empty list.
        if hns_absent(hres, &diagnostic) {
            return Ok(None);
        }
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnEnumerateNetworks(name={name}) failed: HRESULT 0x{hres:08X}; {diagnostic}"
        )));
    }
    let candidates = parse_enumerated_ids(&take_hns_error(networks), "Networks")?;
    for candidate in candidates {
        if network_name_for_id(&candidate)?.as_deref() == Some(name) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn find_endpoint_id_by_name(name: &str) -> Result<Option<Guid>, Report<HcsError>> {
    let query = exact_name_query(name)?;
    let mut endpoints = std::ptr::null_mut();
    let mut error_record = std::ptr::null_mut();
    let hres = unsafe { HcnEnumerateEndpoints(query.as_ptr(), &mut endpoints, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres != S_OK {
        // An absent endpoint surfaces as a not-found enumeration error; that
        // is the same idempotent "already gone" outcome as an empty list.
        if hns_absent(hres, &diagnostic) {
            return Ok(None);
        }
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnEnumerateEndpoints(name={name}) failed: HRESULT 0x{hres:08X}; {diagnostic}"
        )));
    }
    let candidates = parse_enumerated_ids(&take_hns_error(endpoints), "Endpoints")?;
    for candidate in candidates {
        if endpoint_name_for_id(&candidate)?.as_deref() == Some(name) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Tear-down counterpart of [`create_network_and_endpoint_with_callbacks`]. Order:
///   1. Close the endpoint handle.
///   2. Delete the endpoint (by GUID — detach from VM).
///   3. Close the network handle.
///   4. Delete the network (by GUID).
///
/// Each step is best-effort and logged on failure, including any HNS
/// `ErrorRecord` diagnostics the failing call returns. Whole thing is
/// `unsafe`-free from the caller's perspective; the type system gives
/// us the guarantee that handles are non-null — `create_network_and_endpoint`
/// already checked for null on the create path.
///
/// The function is `pub(crate)` and takes ownership so it can be the
/// single-drop-style call from `Vm::drop`. Calling on a `NetworkState`
/// made by [`create_network_and_endpoint_with_callbacks`] is the only way to reach this
/// function.
pub(crate) fn close_and_delete_result(state: NetworkState) -> Result<(), Report<HcsError>> {
    let NetworkState {
        network_id,
        endpoint_id,
        endpoint_handle,
        network_handle,
        endpoint_id_string: _,
    } = state;
    let mut failures = Vec::new();

    let hres = unsafe { HcnCloseEndpoint(endpoint_handle) };
    if hres != S_OK {
        failures.push(format!("HcnCloseEndpoint failed: HRESULT 0x{hres:08X}"));
    }
    if let Err(error) = delete_endpoint(&endpoint_id) {
        failures.push(error.to_string());
    }

    let hres = unsafe { HcnCloseNetwork(network_handle) };
    if hres != S_OK {
        failures.push(format!("HcnCloseNetwork failed: HRESULT 0x{hres:08X}"));
    }
    if let Err(error) = delete_network(&network_id) {
        failures.push(error.to_string());
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(Report::new(HcsError::Network).attach(failures.join("; ")))
    }
}

/// A journaled resource ID classified for deletion: an exact GUID string
/// (braced or unbraced), or a malformed one that must fall back to the
/// exact-name lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalId {
    Exact(Guid),
    Malformed,
}

/// Classify a journaled resource ID. `None` means no ID was journaled
/// (name-based lookup); `Malformed` means the recorded ID cannot be parsed
/// (same fallback, with a warning so the other resource's deletion still
/// proceeds). Braces are stripped before parsing, mirroring
/// [`parse_hns_id`].
fn classify_journal_id(id: Option<&str>) -> Option<JournalId> {
    id.map(|id| {
        let unbraced = id
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .unwrap_or(id);
        match parse_guid_string(unbraced) {
            Some(guid) => JournalId::Exact(guid),
            None => JournalId::Malformed,
        }
    })
}

/// Delete exactly the endpoint and network identities recorded in a journal.
/// An exact recorded GUID is preferred. If a crash occurred before HNS's
/// queried GUID was committed, the exact deterministic name is resolved to a
/// GUID and its properties are checked before deletion. No prefix or owner
/// sweep is permitted.
pub(crate) fn delete_exact(
    network_id: Option<&str>,
    network_name: &str,
    endpoint_id: Option<&str>,
    endpoint_name: &str,
) -> Result<(), Report<HcsError>> {
    let mut failures = Vec::new();
    let endpoint_guid = match classify_journal_id(endpoint_id) {
        Some(JournalId::Exact(guid)) => Some(guid),
        Some(JournalId::Malformed) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                endpoint_id,
                "[HNS] malformed journaled endpoint ID; falling back to name-based deletion"
            );
            find_endpoint_id_by_name(endpoint_name)?
        }
        None => find_endpoint_id_by_name(endpoint_name)?,
    };
    if let Some(guid) = endpoint_guid
        && let Err(error) = delete_endpoint(&guid)
    {
        failures.push(error.to_string());
    }
    let network_guid = match classify_journal_id(network_id) {
        Some(JournalId::Exact(guid)) => Some(guid),
        Some(JournalId::Malformed) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                network_id,
                "[HNS] malformed journaled network ID; falling back to name-based deletion"
            );
            find_network_id_by_name(network_name)?
        }
        None => find_network_id_by_name(network_name)?,
    };
    if let Some(guid) = network_guid
        && let Err(error) = delete_network(&guid)
    {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Report::new(HcsError::Network).attach(failures.join("; ")))
    }
}

fn delete_endpoint(endpoint_id: &Guid) -> Result<(), Report<HcsError>> {
    let mut error_record: *mut u16 = std::ptr::null_mut();
    let hres = unsafe { HcnDeleteEndpoint(endpoint_id, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres == S_OK || hns_absent(hres, &diagnostic) {
        return Ok(());
    }
    Err(Report::new(HcsError::Network).attach(format!(
        "HcnDeleteEndpoint failed: HRESULT 0x{hres:08X}; {diagnostic}"
    )))
}

/// Enumerate every HNS network with its exact GUID string and name, reusing
/// the enumeration and per-ID property queries above. Resources whose name
/// cannot be read (already absent) are skipped. Consumed by the legacy
/// cleanup admin API; the caller is responsible for filtering and for
/// requiring operator confirmation.
pub fn enumerate_networks_with_names() -> Result<Vec<(String, String)>, Report<HcsError>> {
    let query = empty_hns_query()?;
    let mut networks = std::ptr::null_mut();
    let mut error_record = std::ptr::null_mut();
    let hres = unsafe { HcnEnumerateNetworks(query.as_ptr(), &mut networks, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres != S_OK {
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnEnumerateNetworks failed: HRESULT 0x{hres:08X}; {diagnostic}"
        )));
    }
    let ids = parse_enumerated_ids(&take_hns_error(networks), "Networks")?;
    let mut named = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(name) = network_name_for_id(&id)? {
            named.push((format_endpoint_id_string(&id), name));
        }
    }
    Ok(named)
}

/// Endpoint counterpart of [`enumerate_networks_with_names`].
pub fn enumerate_endpoints_with_names() -> Result<Vec<(String, String)>, Report<HcsError>> {
    let query = empty_hns_query()?;
    let mut endpoints = std::ptr::null_mut();
    let mut error_record = std::ptr::null_mut();
    let hres = unsafe { HcnEnumerateEndpoints(query.as_ptr(), &mut endpoints, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres != S_OK {
        return Err(Report::new(HcsError::Network).attach(format!(
            "HcnEnumerateEndpoints failed: HRESULT 0x{hres:08X}; {diagnostic}"
        )));
    }
    let ids = parse_enumerated_ids(&take_hns_error(endpoints), "Endpoints")?;
    let mut named = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(name) = endpoint_name_for_id(&id)? {
            named.push((format_endpoint_id_string(&id), name));
        }
    }
    Ok(named)
}

/// Parse an HNS ID string — braced or unbraced GUID — for an exact-identity
/// delete. Rejects any structural deviation before a delete call is made.
fn parse_hns_id(id: &str, resource: &str) -> Result<Guid, Report<HcsError>> {
    let unbraced = id
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(id);
    parse_guid_string(unbraced).ok_or_else(|| {
        Report::new(HcsError::Network).attach(format!("malformed HNS {resource} ID `{id}`"))
    })
}

/// Delete an HNS network by its exact GUID string (braced or unbraced).
/// Idempotent: an already-absent network succeeds. Used by the legacy
/// cleanup admin API; never sweeps by name prefix or owner.
pub fn delete_network_by_id(id: &str) -> Result<(), Report<HcsError>> {
    let guid = parse_hns_id(id, "network")?;
    delete_network(&guid)
}

/// Delete an HNS endpoint by its exact GUID string (braced or unbraced).
/// Idempotent: an already-absent endpoint succeeds.
pub fn delete_endpoint_by_id(id: &str) -> Result<(), Report<HcsError>> {
    let guid = parse_hns_id(id, "endpoint")?;
    delete_endpoint(&guid)
}

fn delete_network(network_id: &Guid) -> Result<(), Report<HcsError>> {
    let mut error_record: *mut u16 = std::ptr::null_mut();
    let hres = unsafe { HcnDeleteNetwork(network_id, &mut error_record) };
    let diagnostic = take_hns_error(error_record);
    if hres == S_OK || hns_absent(hres, &diagnostic) {
        return Ok(());
    }
    Err(Report::new(HcsError::Network).attach(format!(
        "HcnDeleteNetwork failed: HRESULT 0x{hres:08X}; {diagnostic}"
    )))
}

fn hns_absent(hres: i32, _diagnostic: &str) -> bool {
    // Absence is classified ONLY by the stable HRESULT whitelist HNS uses
    // for "element not found"; error-record TEXT is never matched, because
    // wording is localized and can change between releases.
    matches!(hres as u32, 0x8007_0490 | 0x8007_0002)
}

fn rollback_network_creation(
    network_id: &Guid,
    endpoint_id: Option<&Guid>,
    endpoint_handle: HCN_ENDPOINT,
    network_handle: HCN_NETWORK,
) {
    if !endpoint_handle.is_null() {
        let hres = unsafe { HcnCloseEndpoint(endpoint_handle) };
        if hres != S_OK {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                hresult = format!("0x{hres:08X}"),
                "[hns] rollback endpoint close failed"
            );
        }
    }
    if !network_handle.is_null() {
        let hres = unsafe { HcnCloseNetwork(network_handle) };
        if hres != S_OK {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                hresult = format!("0x{hres:08X}"),
                "[hns] rollback network close failed"
            );
        }
    }
    if let Some(endpoint_id) = endpoint_id
        && let Err(_error) = delete_endpoint(endpoint_id)
    {
        #[cfg(feature = "tracing")]
        tracing::debug!(error = %_error, "[hns] rollback endpoint delete failed");
    }
    if let Err(_error) = delete_network(network_id) {
        #[cfg(feature = "tracing")]
        tracing::debug!(error = %_error, "[hns] rollback network delete failed");
    }
}
