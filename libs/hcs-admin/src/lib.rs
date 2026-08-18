//! Explicit operator-directed HCS inspection and legacy cleanup
//! (SolidArchitecturePlan A12, work package 5 actions 18-19).
//!
//! This crate owns the abandoned-resource inventory, legacy (pre-journal)
//! resource discovery, exact selected deletion, and dry-run data. It is the
//! operator administration surface for HCS: automatic runtime cleanup, VM
//! launch, image acquisition, and guest commands are deliberately forbidden
//! here.
//!
//! It depends only on `hypervisor-hcs`, which owns the HCS lifecycle, the
//! journal, and the exact-removal primitives this crate composes. The crate
//! compiles to an empty library on non-Windows targets.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: hcs-admin.
//!
//! **Responsibility**: explicit operator-directed HCS inspection and cleanup.
//!
//! **Allowed dependencies**: hypervisor-hcs (enforced by
//! `tests/architecture`).
//!
//! **Forbidden concepts**: automatic runtime cleanup, VM launch, image
//! acquisition, and guest commands.

#![cfg(target_os = "windows")]

use error_stack::Report;
use hypervisor_hcs::error::HcsError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hypervisor_hcs::{core::ToWide, ext::*, operation::hcs_operation_sync};

// ---------------------------------------------------------------------------
// Legacy (pre-journal) orphan cleanup
//
// Work package R "Removal of broad cleanup": automatic `Owner == "jyth"`
// sweeps and `jyth-nat-*` prefix sweeps are gone; pre-journal orphans are
// cleaned only by this explicit, dry-run-first administrator API. It never
// guesses — every candidate is reported with its exact ID and name, and
// deletion happens only when an operator confirms the printed list.
// ---------------------------------------------------------------------------

/// The exact HCS owner string written by pre-journal Jyth releases. Journaled
/// resources use `jyth/v1/<session-uuid>` (see `hypervisor_hcs::journal`); only
/// the bare legacy owner is a cleanup candidate. Compared case-sensitively.
const LEGACY_OWNER: &str = "jyth";
/// HNS network name prefix shared by pre-journal and journaled Jyth NAT
/// networks (`jyth-nat-<vm-uuid>`).
const LEGACY_NETWORK_PREFIX: &str = "jyth-nat-";
/// HNS endpoint name prefix shared by pre-journal and journaled Jyth
/// endpoints (`jyth-ep-<vm-uuid>`).
const LEGACY_ENDPOINT_PREFIX: &str = "jyth-ep-";

/// Kind of host resource targeted by the legacy cleanup API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyResourceKind {
    /// An HCS compute system whose owner is exactly `jyth`.
    ComputeSystem,
    /// An HNS network named `jyth-nat-*`.
    Network,
    /// An HNS endpoint named `jyth-ep-*`.
    Endpoint,
}

impl std::fmt::Display for LegacyResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LegacyResourceKind::ComputeSystem => "compute system",
            LegacyResourceKind::Network => "network",
            LegacyResourceKind::Endpoint => "endpoint",
        })
    }
}

/// One legacy resource the operator tool may delete. `id` is the exact
/// host-side identifier (HCS compute-system ID, HNS GUID string); `name` is
/// the friendly HNS name when the resource carries one (compute systems have
/// none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyResource {
    /// The kind of legacy resource (compute system, network, or endpoint).
    pub kind: LegacyResourceKind,
    /// The exact host-side identifier (HCS compute-system ID or HNS GUID
    /// string).
    pub id: String,
    /// The friendly HNS name when the resource carries one; `None` for
    /// compute systems, which have no name.
    pub name: Option<String>,
}

impl std::fmt::Display for LegacyResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)?;
        if let Some(name) = &self.name {
            write!(f, " (name: {name})")?;
        }
        Ok(())
    }
}

/// True when `owner` is exactly the pre-journal owner string `jyth`.
/// Journaled owners (`jyth/v1/<session-uuid>`) never match; the compare is
/// case-sensitive.
fn is_legacy_compute_system_owner(owner: &str) -> bool {
    owner == LEGACY_OWNER
}

/// True when `name` starts with `prefix`, case-insensitively, and carries at
/// least one character after it (a bare `jyth-nat-` is not a resource name).
///
/// Note this cannot distinguish pre-journal from journaled HNS resources:
/// both use the same `jyth-nat-<vm-uuid>` / `jyth-ep-<vm-uuid>` name scheme.
/// That is exactly why the tool prints the exact IDs/names and requires
/// explicit confirmation before deletion.
fn matches_hns_name_prefix(name: &str, prefix: &str) -> bool {
    name.len() > prefix.len()
        && name
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Serialized `HcsEnumerateComputeSystems` query restricted to the legacy
/// owner. HCS filters server-side; the per-entry owner is re-verified with
/// [`is_legacy_compute_system_owner`] before a resource is reported.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct OwnersQuery {
    owners: Vec<String>,
}

/// One compute-system entry of the `HcsEnumerateComputeSystems` result
/// document. `Owner` is present on current HCS builds (the same field
/// hcsshim's `ContainerProperties` carries); an entry without an owner is
/// never treated as legacy.
#[derive(Debug, Deserialize)]
struct ComputeSystemEntry {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Owner", default)]
    owner: Option<String>,
}

/// Enumerate HCS compute systems and keep only pre-journal legacy resources:
/// entries whose owner is exactly `jyth`. Journaled `jyth/v1/...` owners
/// never match — the query restricts server-side AND each entry's owner is
/// re-checked with the exact compare.
pub fn list_legacy_compute_systems() -> Result<Vec<LegacyResource>, Report<HcsError>> {
    let query = OwnersQuery {
        owners: vec![LEGACY_OWNER.to_owned()],
    };
    let query_json = serde_json::to_string(&query)
        .map_err(|error| Report::new(error).change_context(HcsError::Serialize))?;
    let wide_query = query_json.to_wide();
    let doc_str =
        hcs_operation_sync(|op| unsafe { HcsEnumerateComputeSystems(wide_query.as_ptr(), op) })?
            .ok_or_else(|| {
                Report::new(HcsError::Enumeration)
                    .attach("HcsEnumerateComputeSystems returned null")
            })?;
    let entries: Vec<ComputeSystemEntry> = serde_json::from_str(&doc_str)
        .map_err(|error| Report::new(error).change_context(HcsError::Deserialize))?;
    Ok(legacy_compute_systems_from_entries(entries))
}

/// Pure mapping: filter enumerated entries to legacy owners and map them to
/// [`LegacyResource`] values. Kept separate from the FFI call so the owner
/// discrimination is unit-testable without a live HCS.
fn legacy_compute_systems_from_entries(entries: Vec<ComputeSystemEntry>) -> Vec<LegacyResource> {
    entries
        .into_iter()
        .filter(|entry| {
            entry
                .owner
                .as_deref()
                .is_some_and(is_legacy_compute_system_owner)
        })
        .map(|entry| LegacyResource {
            kind: LegacyResourceKind::ComputeSystem,
            id: entry.id,
            name: None,
        })
        .collect()
}

/// Enumerate HNS networks and keep only those whose name starts with
/// `jyth-nat-` (case-insensitive), carrying the exact GUID string and name.
///
/// The name-prefix filter CANNOT distinguish pre-journal from journaled
/// resources — both use the same name scheme — so callers must print the
/// exact IDs and names and require explicit confirmation before deleting.
pub fn list_legacy_networks() -> Result<Vec<LegacyResource>, Report<HcsError>> {
    Ok(legacy_hns_resources(
        hypervisor_hcs::hns::enumerate_networks_with_names()?,
        LEGACY_NETWORK_PREFIX,
        LegacyResourceKind::Network,
    ))
}

/// Enumerate HNS endpoints and keep only those whose name starts with
/// `jyth-ep-` (case-insensitive). Same journaled/legacy caveat as
/// [`list_legacy_networks`].
pub fn list_legacy_endpoints() -> Result<Vec<LegacyResource>, Report<HcsError>> {
    Ok(legacy_hns_resources(
        hypervisor_hcs::hns::enumerate_endpoints_with_names()?,
        LEGACY_ENDPOINT_PREFIX,
        LegacyResourceKind::Endpoint,
    ))
}

/// Pure mapping: filter `(id, name)` pairs to the prefix and map them to
/// [`LegacyResource`] values. Unit-testable without a live HNS.
fn legacy_hns_resources(
    named: Vec<(String, String)>,
    prefix: &str,
    kind: LegacyResourceKind,
) -> Vec<LegacyResource> {
    named
        .into_iter()
        .filter(|(_, name)| matches_hns_name_prefix(name, prefix))
        .map(|(id, name)| LegacyResource {
            kind,
            id,
            name: Some(name),
        })
        .collect()
}

/// Delete exactly one legacy compute system by its exact ID. Reuses the
/// journaled exact-remove path (`remove_compute_system_by_id_sync`), so a
/// system that is already absent is treated as successful idempotent cleanup.
/// No prefix or owner sweep is performed here.
pub fn delete_legacy_compute_system(id: &str) -> Result<(), Report<HcsError>> {
    hypervisor_hcs::vm::remove_compute_system_by_id_sync(id)
}

/// Delete exactly one HNS network by its exact GUID string (braced or
/// unbraced). Idempotent: an already-absent network succeeds.
pub fn delete_legacy_network(id: &str) -> Result<(), Report<HcsError>> {
    hypervisor_hcs::hns::delete_network_by_id(id)
}

/// Delete exactly one HNS endpoint by its exact GUID string (braced or
/// unbraced). Idempotent: an already-absent endpoint succeeds.
pub fn delete_legacy_endpoint(id: &str) -> Result<(), Report<HcsError>> {
    hypervisor_hcs::hns::delete_endpoint_by_id(id)
}

// ---------------------------------------------------------------------------
// Hyper-V Administrators access
//
// Pre-flight operator step for HCS access: HCS rejects every call with
// HRESULT 0x8037011B unless the caller's token belongs to the local
// "Hyper-V Administrators" group (S-1-5-32-578). This wrapper surfaces the
// detection/remediation of missing membership as an explicit, operator-
// invokable step.
// ---------------------------------------------------------------------------

/// Operator-facing Hyper-V Administrators membership step.
///
/// Detects whether the current process token belongs to the local
/// "Hyper-V Administrators" group (S-1-5-32-578 — the HCS access
/// requirement; HRESULT 0x8037011B otherwise). When membership is
/// missing, prompts once via the OS UAC consent dialog and adds the
/// *current* user to the group through an elevated shell
/// (`powershell.exe`, falling back to `pwsh.exe`).
///
/// `Ok(())` means the token already carries the group and nothing was
/// done. `Err` always carries an attached message describing the exact
/// outcome: the user was added (effective at the NEXT logon — Windows
/// computes group membership at logon time, so sign out/in or reboot
/// and retry), the UAC prompt was declined, or the add failed (with the
/// manual elevated command included). Only ever affects the current
/// user; the OS consent dialog is the permission gate.
pub fn ensure_hyperv_admin_access() -> Result<(), Report<HcsError>> {
    hypervisor_hcs::hyperv::ensure_hyperv_admin_membership()
}

/// Environment consent gate for the operator remediation steps.
///
/// Consent is a launch-environment decision: the operator sets
/// `JYTH_ADMIN_CONSENT=1` (or `true`/`yes`, case-insensitive) when they
/// want the remediation steps to act. There is deliberately NO interactive
/// prompt: automation (CI, agents, scripts) must opt in explicitly, and a
/// run without consent must fail loudly instead of silently declining.
const ADMIN_CONSENT_ENV: &str = "JYTH_ADMIN_CONSENT";

/// True when `value` is an accepted consent value (`1`, `true`, `yes`,
/// case-insensitive, after trimming).
fn is_consent_value(value: &str) -> bool {
    let v = value.trim();
    v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
}

/// The actionable refusal message naming the consent environment variable.
/// Kept as a pure string so the alert can be unit-tested without touching
/// the environment.
fn consent_refusal() -> String {
    format!(
        "refusing the remediation step without explicit operator consent: \
         set {ADMIN_CONSENT_ENV}=1 (or true/yes) in the launch environment to allow \
         automatic HCS/HNS remediation"
    )
}

/// Require explicit environment consent for a remediation step. Returns
/// `Ok(())` when `JYTH_ADMIN_CONSENT` is set to an accepted value; returns
/// the actionable refusal otherwise (never prompts, never auto-consents).
fn require_consent() -> Result<(), Report<HcsError>> {
    match std::env::var(ADMIN_CONSENT_ENV) {
        Ok(value) if is_consent_value(&value) => {
            #[cfg(feature = "tracing")]
            tracing::debug!(env = ADMIN_CONSENT_ENV, "remediation consent granted");
            Ok(())
        }
        _ => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                env = ADMIN_CONSENT_ENV,
                "remediation consent refused by environment"
            );
            Err(Report::new(HcsError::HyperVAdmin).attach(consent_refusal()))
        }
    }
}

// ---------------------------------------------------------------------------
// Stale HNS network cleanup
//
// Pre-flight operator step for a clean HNS slate. HNS networks survive
// reboots, so a `jyth-nat-*` network left by an aborted run makes every
// later network-adapter block against it fail (VM create HRESULT
// 0x80370110). Candidates are listed (dry-run first, the house rule) and
// removed ONLY when the launch environment carries `JYTH_ADMIN_CONSENT` —
// never silently, and never touching non-Jyth networks.
// ---------------------------------------------------------------------------

/// Outcome of [`cleanup_stale_jyth_networks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HnsCleanupOutcome {
    /// No `jyth-nat-*` network exists; nothing to do.
    NoneFound,
    /// Stale network(s) were found and, with `JYTH_ADMIN_CONSENT`, deleted.
    Removed { ids: Vec<String> },
}

/// Operator-directed stale HNS network cleanup.
///
/// Enumerates HNS networks in-process and looks for Jyth-owned NAT
/// networks (`jyth-nat-*`). When stale ones exist — typically left by an
/// aborted run — they are listed (dry-run first, the house rule) and
/// removed ONLY when the launch environment carries consent: deletion is
/// gated by the `JYTH_ADMIN_CONSENT` environment variable, never a
/// console prompt. Without consent the step refuses loudly (the error
/// names the variable) and no prompt is shown. Removal is exact by
/// network GUID via [`delete_legacy_network`]; only the Jyth namespace
/// prefix is ever a candidate, and non-Jyth networks are never touched.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "debug"))]
pub fn cleanup_stale_jyth_networks() -> Result<HnsCleanupOutcome, Report<HcsError>> {
    let candidates = stale_network_candidates(
        hypervisor_hcs::hns::enumerate_networks_with_names().map_err(|error| {
            error.attach(
                "HNS inspection failed; elevated Get-HnsNetwork / Remove-HnsNetwork \
                 remain the manual fallback",
            )
        })?,
    );
    #[cfg(feature = "tracing")]
    tracing::info!(count = candidates.len(), "stale Jyth HNS networks found");
    for (id, name) in &candidates {
        eprintln!("stale Jyth HNS network: {name} ({id})");
    }
    if !candidates.is_empty() {
        require_consent()?;
    }
    let HnsCleanupOutcome::Removed { ids } = decide_cleanup(candidates) else {
        return Ok(HnsCleanupOutcome::NoneFound);
    };
    let mut deleted = Vec::with_capacity(ids.len());
    for id in ids {
        delete_legacy_network(&id).map_err(|error| {
            error.attach(format!("failed to remove stale Jyth HNS network {id}"))
        })?;
        #[cfg(feature = "tracing")]
        tracing::debug!(id = %id, "removed stale Jyth HNS network");
        deleted.push(id);
    }
    Ok(HnsCleanupOutcome::Removed { ids: deleted })
}

/// Pure filter: keep only the `(id, name)` pairs whose name starts with
/// the Jyth NAT network prefix (case-insensitive). Reuses
/// [`matches_hns_name_prefix`].
fn stale_network_candidates(named: Vec<(String, String)>) -> Vec<(String, String)> {
    named
        .into_iter()
        .filter(|(_, name)| matches_hns_name_prefix(name, LEGACY_NETWORK_PREFIX))
        .collect()
}

/// Pure decision: map the enumerated candidates to the cleanup outcome.
/// Consent is not part of the mapping — [`require_consent`] gates the
/// deletion separately — so this is unit-testable without a live HNS or
/// environment mutation.
fn decide_cleanup(candidates: Vec<(String, String)>) -> HnsCleanupOutcome {
    if candidates.is_empty() {
        return HnsCleanupOutcome::NoneFound;
    }
    HnsCleanupOutcome::Removed {
        ids: candidates.into_iter().map(|(id, _)| id).collect::<Vec<_>>(),
    }
}

// ---------------------------------------------------------------------------
// HCS compute-stack restart
//
// Reactive remediation for the code-run adapter-block signature (HRESULT
// 0x80370110): when the HCS/HNS compute stack is degraded, the kernel
// build step may restart `vmcompute` + `hns` and retry its launch once.
// Consent is a launch-environment decision (`JYTH_ADMIN_CONSENT`), never a
// console prompt; the restart itself runs elevated (UAC dialog) so the
// step never needs an elevated host process.
// ---------------------------------------------------------------------------

/// The elevated PowerShell command performing the restart: restart both
/// services, let them settle, verify both are `Running`, and report via
/// the exit code (0 both Running, 1 restart ran but not Running, 2 the
/// command itself failed via the catch block). Static — no user input.
const COMPUTE_RESTART_PS: &str = "try { Restart-Service vmcompute -ErrorAction Stop; \
    Restart-Service hns -ErrorAction Stop; Start-Sleep -Seconds 2; \
    $bad = Get-Service vmcompute, hns | Where-Object { $_.Status -ne 'Running' }; \
    if (@($bad).Count -eq 0) { exit 0 } else { exit 1 } \
    } catch { exit 2 }";

/// How long the elevated restart may run before it is reported as still
/// pending — a service restart plus the settle delay needs longer than
/// the membership step's 30 s budget.
const RESTART_WAIT_MS: u32 = 120_000;

/// The full argument string for the elevated shell:
/// `-NoProfile -NonInteractive -Command <quoted>`. The command is a
/// static string quoted per the Win32 argv rules so it round-trips as a
/// single argument. Kept as a function so the unit tests can pin the
/// exact restart command without running it.
fn restart_params() -> String {
    format!(
        "-NoProfile -NonInteractive -Command {}",
        hypervisor_hcs::hyperv::quote_windows_command_line_arg(COMPUTE_RESTART_PS)
    )
}

/// Pure mapping from the elevated restart exit code to the step result:
/// no exit code at all (UAC declined / no shell available) → the refusal
/// error; exit 0 → `Ok(())`; exit 1 → the restart ran but a service is
/// not Running; any other exit code (including the command's catch-block
/// 2) → the restart command failed. Kept separate from the launch loop so
/// the mapping is unit-testable without elevation or live services.
fn decide_restart(exit: Option<u32>) -> Result<(), Report<HcsError>> {
    let Some(exit) = exit else {
        return Err(Report::new(HcsError::Network)
            .attach("the elevated restart was declined (UAC prompt) or no shell is available"));
    };
    match exit {
        0 => Ok(()),
        1 => {
            Err(Report::new(HcsError::Network)
                .attach("restart ran but vmcompute/hns is not Running"))
        }
        code => Err(Report::new(HcsError::Network)
            .attach(format!("restart command failed (exit code {code})"))),
    }
}

/// Operator-directed HCS compute-stack restart.
///
/// Restarts `vmcompute` and `hns` (the HCS/HNS services) when the adapter-
/// block failure signature (`0x80370110`) indicates a degraded compute
/// stack. This KILLS any running VMs/containers on the host, so consent
/// is the `JYTH_ADMIN_CONSENT` environment variable — a launch-
/// environment decision, never a console prompt; a run without it refuses
/// loudly (the error names the variable) and shows no prompt. The UAC
/// consent dialog remains the OS-level consent for the elevation itself.
/// Both services are verified Running before `Ok(())` is returned.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "debug"))]
pub fn restart_compute_services() -> Result<(), Report<HcsError>> {
    require_consent()?;

    let params = restart_params();

    // Two-shell fallback mirroring `ensure_hyperv_admin_membership`: try
    // Windows PowerShell first, then PowerShell Core. ERROR_FILE_NOT_FOUND
    // means "try the next candidate"; any other launch error (e.g. the
    // user declining the UAC prompt, or no shell at all) is reported as a
    // refused elevated restart — nothing is restarted without the
    // operator's consent to the elevated run.
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    #[cfg(feature = "tracing")]
    tracing::info!("restarting vmcompute + hns with UAC consent");
    for shell in ["powershell.exe", "pwsh.exe"] {
        let exit_code =
            match hypervisor_hcs::hyperv::launch_elevated(shell, &params, RESTART_WAIT_MS) {
                Ok(code) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(exit_code = code, "compute-stack restart command finished");
                    code
                }
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => continue,
                Err(_) => return decide_restart(None),
            };
        return decide_restart(Some(exit_code));
    }

    // Neither powershell.exe nor pwsh.exe exists on this host — same
    // refusal path as the UAC-declined case.
    decide_restart(None)
}

// ---------------------------------------------------------------------------
// Abandoned inventory
//
// Records that exhausted `MAX_CLEANUP_ATTEMPTS` automatic recovery passes
// are preserved (with their exact identity and last error) in the session
// databases of the state root. This query lists them for operator review.
// It is deliberately read-only: removal stays a deliberate, operator-
// confirmed action.
// ---------------------------------------------------------------------------

/// One host resource left behind by a record that exhausted its automatic
/// cleanup attempts. `identity` is the exact host-side identifier recorded
/// in the journal (compute-system ID, `network/endpoint` names, or disk
/// path); `last_error` carries `resource_kind`/`operation`/`resource_id`/
/// `cause` context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonedResource {
    /// The resource kind recorded in the journal (e.g. compute system,
    /// network, endpoint, disk).
    pub kind: String,
    /// The exact host-side identifier recorded in the journal.
    pub identity: String,
    /// The persisted failure context carrying
    /// `resource_kind`/`operation`/`resource_id`/`cause`.
    pub last_error: String,
    /// Unix timestamp (milliseconds) of the first abandoned transition.
    pub first_abandoned_at_unix_ms: u64,
}

/// All abandoned resources of one VM, as recorded in one stale session
/// database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonedVm {
    /// The VM whose stale session recorded the abandoned resources.
    pub vm_id: Uuid,
    /// Every abandoned resource of that VM, in journal order.
    pub resources: Vec<AbandonedResource>,
}

/// List every abandoned resource recorded in the stale session databases of
/// the state root. Read-only: sessions still locked by a live process are
/// skipped, and no database is modified.
pub fn list_abandoned_resources() -> Result<Vec<AbandonedVm>, Report<HcsError>> {
    Ok(abandoned_vms_from_records(
        hypervisor_hcs::journal::abandoned_inventory(
            &hypervisor_hcs::journal::resolve_state_root()?,
        )?,
    ))
}

/// Pure mapping from journal records to the public inventory types.
/// Kept separate from the database scan so the mapping is unit-testable
/// without touching the state root.
fn abandoned_vms_from_records(
    records: Vec<hypervisor_hcs::journal::AbandonedRecord>,
) -> Vec<AbandonedVm> {
    records
        .into_iter()
        .map(|record| AbandonedVm {
            vm_id: record.vm_id,
            resources: record
                .entries
                .into_iter()
                .map(|entry| AbandonedResource {
                    kind: entry.kind,
                    identity: entry.identity,
                    last_error: entry.last_error,
                    first_abandoned_at_unix_ms: entry.first_abandoned_at_unix_ms,
                })
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_owner_filter_matches_exact_jyth_only() {
        assert!(is_legacy_compute_system_owner("jyth"));
        assert!(!is_legacy_compute_system_owner(
            "jyth/v1/019f6828-9125-7261-8ad4-11e2402516f1"
        ));
        assert!(!is_legacy_compute_system_owner("JYTH"));
        assert!(!is_legacy_compute_system_owner("jyth/v1"));
        assert!(!is_legacy_compute_system_owner("VMMS"));
        assert!(!is_legacy_compute_system_owner(""));
    }

    #[test]
    fn hns_prefix_filter_matches_jyth_nat_and_ep_names() {
        let uuid = "019f6828-9125-7261-8ad4-11e2402516f1";
        assert!(matches_hns_name_prefix(
            &format!("jyth-nat-{uuid}"),
            LEGACY_NETWORK_PREFIX
        ));
        assert!(matches_hns_name_prefix(
            &format!("jyth-ep-{uuid}"),
            LEGACY_ENDPOINT_PREFIX
        ));
        // Case-insensitive prefix match.
        assert!(matches_hns_name_prefix(
            &format!("JYTH-NAT-{uuid}"),
            LEGACY_NETWORK_PREFIX
        ));
        assert!(matches_hns_name_prefix(
            &format!("Jyth-Ep-{uuid}"),
            LEGACY_ENDPOINT_PREFIX
        ));
        // A bare prefix is not a resource name.
        assert!(!matches_hns_name_prefix("jyth-nat-", LEGACY_NETWORK_PREFIX));
        assert!(!matches_hns_name_prefix("jyth-nat", LEGACY_NETWORK_PREFIX));
        // Unrelated names never match.
        assert!(!matches_hns_name_prefix(
            &format!("other-nat-{uuid}"),
            LEGACY_NETWORK_PREFIX
        ));
        assert!(!matches_hns_name_prefix("", LEGACY_NETWORK_PREFIX));
        // The two prefixes never cross-match.
        assert!(!matches_hns_name_prefix(
            &format!("jyth-nat-{uuid}"),
            LEGACY_ENDPOINT_PREFIX
        ));
        assert!(!matches_hns_name_prefix(
            &format!("jyth-ep-{uuid}"),
            LEGACY_NETWORK_PREFIX
        ));
    }

    #[test]
    fn entries_with_journaled_or_missing_owners_are_excluded() {
        let entries = vec![
            ComputeSystemEntry {
                id: "legacy-guid".to_owned(),
                owner: Some("jyth".to_owned()),
            },
            ComputeSystemEntry {
                id: "journaled-guid".to_owned(),
                owner: Some("jyth/v1/019f6828-9125-7261-8ad4-11e2402516f1".to_owned()),
            },
            ComputeSystemEntry {
                id: "no-owner-guid".to_owned(),
                owner: None,
            },
            ComputeSystemEntry {
                id: "other-owner-guid".to_owned(),
                owner: Some("VMMS".to_owned()),
            },
        ];
        let legacy = legacy_compute_systems_from_entries(entries);
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].id, "legacy-guid");
        assert_eq!(legacy[0].kind, LegacyResourceKind::ComputeSystem);
        assert_eq!(legacy[0].name, None);
    }

    #[test]
    fn hns_entries_map_kind_id_and_name() {
        let named = vec![
            (
                "net-legacy".to_owned(),
                "jyth-nat-019f6828-9125-7261-8ad4-11e2402516f1".to_owned(),
            ),
            ("net-other".to_owned(), "other".to_owned()),
        ];
        let legacy =
            legacy_hns_resources(named, LEGACY_NETWORK_PREFIX, LegacyResourceKind::Network);
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].id, "net-legacy");
        assert_eq!(
            legacy[0].name.as_deref(),
            Some("jyth-nat-019f6828-9125-7261-8ad4-11e2402516f1")
        );
    }

    #[test]
    fn resource_display_includes_name_when_present() {
        let with_name = LegacyResource {
            kind: LegacyResourceKind::Network,
            id: "net-guid".to_owned(),
            name: Some("jyth-nat-demo".to_owned()),
        };
        let without_name = LegacyResource {
            kind: LegacyResourceKind::ComputeSystem,
            id: "system-guid".to_owned(),
            name: None,
        };
        assert_eq!(with_name.to_string(), "net-guid (name: jyth-nat-demo)");
        assert_eq!(without_name.to_string(), "system-guid");
    }

    #[test]
    fn hns_delete_helpers_reject_malformed_ids_without_ffi() {
        assert!(delete_legacy_network("not-a-guid").is_err());
        assert!(delete_legacy_network("{not-a-guid}").is_err());
        assert!(delete_legacy_endpoint("not-a-guid").is_err());
        assert!(delete_legacy_endpoint("").is_err());
    }

    #[test]
    fn abandoned_inventory_mapping_preserves_kind_identity_and_error() {
        use hypervisor_hcs::journal::{AbandonedRecord, AbandonedResourceEntry};
        let vm_id = Uuid::now_v7();
        let records = vec![AbandonedRecord {
            schema_version: hypervisor_hcs::journal::SCHEMA_VERSION,
            vm_id,
            entries: vec![
                AbandonedResourceEntry {
                    kind: "compute_system".to_owned(),
                    identity: vm_id.to_string(),
                    last_error: "resource_kind=compute_system operation=remove \
                        resource_id=019f6828-9125-7261-8ad4-11e2402516f1 \
                        cause=access is denied"
                        .to_owned(),
                    first_abandoned_at_unix_ms: 42,
                },
                AbandonedResourceEntry {
                    kind: "disk".to_owned(),
                    identity: r"C:\disks\leaked.vhdx".to_owned(),
                    last_error: "resource_kind=disk operation=remove \
                        resource_id=C:\\disks\\leaked.vhdx cause=sharing violation"
                        .to_owned(),
                    first_abandoned_at_unix_ms: 43,
                },
            ],
        }];
        let mapped = abandoned_vms_from_records(records);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].vm_id, vm_id);
        assert_eq!(mapped[0].resources.len(), 2);
        assert_eq!(mapped[0].resources[0].kind, "compute_system");
        assert_eq!(mapped[0].resources[0].first_abandoned_at_unix_ms, 42);
        assert!(
            mapped[0].resources[0]
                .last_error
                .contains("resource_id=019f6828-9125-7261-8ad4-11e2402516f1"),
            "persisted last_error must be self-describing"
        );
        assert_eq!(mapped[0].resources[1].identity, r"C:\disks\leaked.vhdx");
    }

    #[test]
    fn stale_network_candidates_keeps_only_jyth_nat_names() {
        let uuid = "019f6828-9125-7261-8ad4-11e2402516f1";
        let named = vec![
            (format!("net-{uuid}"), format!("jyth-nat-{uuid}")),
            (format!("net-upper-{uuid}"), format!("JYTH-NAT-{uuid}")),
            (format!("ep-{uuid}"), format!("jyth-ep-{uuid}")),
            (format!("net-other-{uuid}"), format!("other-nat-{uuid}")),
            (format!("net-bare-{uuid}"), "jyth-nat-".to_owned()),
        ];
        let candidates = stale_network_candidates(named);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].0, format!("net-{uuid}"));
        assert_eq!(candidates[1].0, format!("net-upper-{uuid}"));
    }

    #[test]
    fn consent_value_parser_accepts_accepted_values_only() {
        for value in ["1", "true", "yes", "TRUE", "Yes", " 1 "] {
            assert!(is_consent_value(value), "{value:?} must grant consent");
        }
        for value in ["0", "false", "no", "", "garbage"] {
            assert!(!is_consent_value(value), "{value:?} must refuse consent");
        }
    }

    #[test]
    fn consent_refusal_mentions_the_environment_variable() {
        let refusal = consent_refusal();
        assert!(
            refusal.contains("JYTH_ADMIN_CONSENT"),
            "the refusal must name the consent variable: {refusal}"
        );
    }

    #[test]
    fn cleanup_decision_maps_none_and_removed() {
        let candidates = vec![
            ("net-a".to_owned(), "jyth-nat-a".to_owned()),
            ("net-b".to_owned(), "jyth-nat-b".to_owned()),
        ];
        assert_eq!(decide_cleanup(vec![]), HnsCleanupOutcome::NoneFound);
        assert_eq!(
            decide_cleanup(candidates),
            HnsCleanupOutcome::Removed {
                ids: vec!["net-a".to_owned(), "net-b".to_owned()]
            }
        );
    }

    #[test]
    fn restart_params_restarts_both_services_and_verifies_running() {
        let params = restart_params();
        assert!(
            params.starts_with("-NoProfile -NonInteractive -Command "),
            "params must use the non-interactive elevated shell: {params}"
        );
        assert!(
            params.contains("Restart-Service vmcompute"),
            "params must restart vmcompute: {params}"
        );
        assert!(
            params.contains("Restart-Service hns"),
            "params must restart hns: {params}"
        );
        assert!(
            params.contains("Get-Service vmcompute, hns")
                && params.contains("Status -ne 'Running'"),
            "params must verify both services are Running: {params}"
        );
    }

    #[test]
    fn restart_decision_maps_exit_codes() {
        assert!(decide_restart(Some(0)).is_ok(), "exit 0 must succeed");
        let no_exit = decide_restart(None).expect_err("no exit code must error");
        assert!(
            format!("{no_exit:?}").contains("declined"),
            "no exit code must report the declined elevation: {no_exit:?}"
        );
        let not_running = decide_restart(Some(1)).expect_err("exit 1 must error");
        assert!(
            format!("{not_running:?}").contains("not Running"),
            "exit 1 must report the unverified service: {not_running:?}"
        );
        for code in [2, 3, 259] {
            let failed = decide_restart(Some(code)).expect_err("non-zero exit must error");
            assert!(
                format!("{failed:?}").contains("restart command failed"),
                "exit {code} must report the command failure: {failed:?}"
            );
        }
    }
}
