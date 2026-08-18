//! Architecture enforcement for the Jyth workspace.
//!
//! This crate exists only to run its test suite (`cargo test -p
//! architecture-tests`); the whole module is `#[cfg(test)]` so the lib target
//! stays empty for other build profiles.
#![cfg(test)]

//! Reads the workspace graph through `cargo metadata` and validates it
//! against the declarative manifest in `architecture.toml` (see
//! `impl/SolidArchitecturePlan.md` for the source-of-truth target graph).
//!
//! Rules enforced:
//! - every workspace package appears exactly once in the manifest
//!   (production, planned production, or non-production);
//! - every production dependency edge is declared (allowed or temporary);
//! - every temporary edge names a removal phase;
//! - no production dependency cycles;
//! - no production package depends on a non-production package;
//! - planned crates, once present, must satisfy their declared edges
//!   (in particular, `jyth-runtime` may depend only on contracts and
//!   generic services — no concrete backend or adapter).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

const MANIFEST: &str = include_str!("../architecture.toml");

/// One package declaration from the manifest.
#[derive(Debug, Clone, Deserialize)]
struct PackageEntry {
    #[serde(default)]
    planned: bool,
    /// Short layer identifier (model, wire, transport, materialization,
    /// guest, coordination, platform, facade, use-case, ...).
    #[serde(default)]
    layer: String,
    /// Primary responsibility identifier from the target crate catalog.
    #[serde(default)]
    responsibility: String,
    /// Normal (non-dev) production dependency edges.
    #[serde(default)]
    allowed: Vec<String>,
    /// Dev-only production dependency edges.
    #[serde(default)]
    allowed_dev: Vec<String>,
    /// Transitional edges that must be removed by the named phase.
    #[serde(default)]
    temporary: Vec<TemporaryEdge>,
}

#[derive(Debug, Clone, Deserialize)]
struct TemporaryEdge {
    to: String,
    #[serde(default = "default_normal_kind")]
    kind: String,
    expires_in: String,
}

fn default_normal_kind() -> String {
    "normal".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
struct ArchitectureManifest {
    packages: BTreeMap<String, PackageEntry>,
    #[serde(rename = "non-production")]
    non_production: NonProduction,
}

#[derive(Debug, Clone, Deserialize)]
struct NonProduction {
    members: Vec<String>,
}

/// A workspace-internal dependency edge discovered by cargo metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    from: String,
    to: String,
    /// "normal" or "dev".
    kind: String,
}

/// Metadata subset we need from `cargo metadata --format-version 1`.
#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    name: String,
    dependencies: Vec<MetadataDependency>,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    /// None or "normal" for regular deps; "dev" for dev-dependencies;
    /// "build" for build-dependencies.
    #[serde(default)]
    kind: Option<String>,
    /// Path dependencies are workspace-internal; registry deps have a source.
    #[serde(default)]
    source: Option<String>,
}

fn workspace_root() -> &'static Path {
    // tests/architecture -> workspace root (two levels up).
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root must be canonicalizable")
    })
}

fn load_metadata() -> Metadata {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        // Only workspace members appear in `packages`; their `dependencies`
        // lists are still populated, and external crates carry a `source`.
        .arg("--no-deps")
        .current_dir(workspace_root())
        .output()
        .expect("failed to run `cargo metadata`");
    assert!(
        output.status.success(),
        "`cargo metadata` failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata output must parse as JSON")
}

fn load_manifest() -> ArchitectureManifest {
    toml::from_str(MANIFEST).expect("architecture.toml must parse")
}

/// Discover workspace-internal edges (path dependencies) for every package.
fn collect_edges(metadata: &Metadata) -> (Vec<Edge>, BTreeSet<String>) {
    let mut edges = Vec::new();
    let mut names = BTreeSet::new();
    for package in &metadata.packages {
        names.insert(package.name.clone());
        for dependency in &package.dependencies {
            if dependency.source.is_some() {
                continue; // external crates are not architecture edges
            }
            if dependency.kind.as_deref() == Some("build") {
                continue; // build-dependencies are not production edges
            }
            let kind = if dependency.kind.as_deref() == Some("dev") {
                "dev"
            } else {
                "normal"
            };
            edges.push(Edge {
                from: package.name.clone(),
                to: dependency.name.clone(),
                kind: kind.to_owned(),
            });
        }
    }
    (edges, names)
}

fn assert_every_package_declared_once(manifest: &ArchitectureManifest, names: &BTreeSet<String>) {
    let mut declared = BTreeSet::new();
    for (name, entry) in &manifest.packages {
        assert!(
            declared.insert(name.clone()),
            "package declared more than once: {name}"
        );
        // Planned crates are declared before they exist; everything else
        // must resolve to a real workspace package.
        if !entry.planned {
            assert!(
                names.contains(name),
                "manifest declares unknown package {name} (not in workspace metadata)"
            );
        }
        // Every production package carries one primary responsibility and a
        // layer (required by the target crate catalog). Planned entries are
        // checked for readiness only.
        if !entry.planned {
            assert!(
                !entry.responsibility.trim().is_empty(),
                "package {name} has no declared primary responsibility"
            );
            assert!(
                !entry.layer.trim().is_empty(),
                "package {name} has no declared layer"
            );
        }
    }
    for name in &manifest.non_production.members {
        assert!(
            declared.insert(name.clone()),
            "package declared more than once: {name}"
        );
        assert!(
            names.contains(name),
            "manifest declares unknown package {name} (not in workspace metadata)"
        );
    }
    for name in names {
        assert!(
            declared.contains(name),
            "workspace package {name} is absent from the architecture manifest"
        );
    }
}

fn assert_edges_declared(manifest: &ArchitectureManifest, edges: &[Edge]) {
    for edge in edges {
        let Some(entry) = manifest.packages.get(&edge.from) else {
            // Non-production packages may depend on anything.
            continue;
        };
        let allowed = if edge.kind == "dev" {
            &entry.allowed_dev
        } else {
            &entry.allowed
        };
        let declared = allowed.iter().any(|to| to == &edge.to)
            || entry
                .temporary
                .iter()
                .any(|temporary| temporary.to == edge.to && temporary.kind == edge.kind);
        assert!(
            declared,
            "undeclared production edge: {} -> {} ({})",
            edge.from, edge.to, edge.kind
        );
    }
}

fn assert_temporary_edges_have_removal_phases(manifest: &ArchitectureManifest) {
    for (package, entry) in &manifest.packages {
        for temporary in &entry.temporary {
            assert!(
                !temporary.expires_in.trim().is_empty(),
                "temporary edge {package} -> {} has no removal phase",
                temporary.to
            );
        }
    }
}

fn assert_no_production_cycles(manifest: &ArchitectureManifest, edges: &[Edge]) {
    // Production adjacency over normal edges only (dev edges may cycle).
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in edges {
        if edge.kind != "normal" {
            continue;
        }
        if !manifest.packages.contains_key(&edge.from) || !manifest.packages.contains_key(&edge.to)
        {
            continue;
        }
        adjacency
            .entry(edge.from.as_str())
            .or_default()
            .push(&edge.to);
    }

    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Visiting,
        Done,
    }
    fn visit<'a>(
        node: &'a str,
        adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
        state: &mut BTreeMap<&'a str, State>,
        stack: &mut Vec<&'a str>,
    ) {
        if state.get(node) == Some(&State::Done) {
            return;
        }
        if state.get(node) == Some(&State::Visiting) {
            let start = stack
                .iter()
                .position(|entry| entry == &node)
                .expect("visiting node must be on the stack");
            let cycle: Vec<&str> = stack[start..].iter().copied().chain([node]).collect();
            panic!("production dependency cycle: {}", cycle.join(" -> "));
        }
        state.insert(node, State::Visiting);
        stack.push(node);
        if let Some(targets) = adjacency.get(node) {
            for target in targets {
                visit(target, adjacency, state, stack);
            }
        }
        stack.pop();
        state.insert(node, State::Done);
    }

    let mut state = BTreeMap::new();
    let mut stack = Vec::new();
    let nodes: Vec<String> = adjacency.keys().map(|key| (*key).to_owned()).collect();
    for node in &nodes {
        visit(node, &adjacency, &mut state, &mut stack);
    }
}

fn assert_no_production_to_non_production_edges(manifest: &ArchitectureManifest, edges: &[Edge]) {
    let non_production: BTreeSet<&str> = manifest
        .non_production
        .members
        .iter()
        .map(|name| name.as_str())
        .collect();
    for edge in edges {
        if manifest.packages.contains_key(&edge.from) && non_production.contains(edge.to.as_str()) {
            panic!(
                "production package {} depends on non-production package {}",
                edge.from, edge.to
            );
        }
    }
}

fn load() -> (ArchitectureManifest, Metadata) {
    let metadata = load_metadata();
    let manifest = load_manifest();
    (manifest, metadata)
}

#[test]
fn every_workspace_package_is_declared_exactly_once() {
    let (manifest, metadata) = load();
    let (_, names) = collect_edges(&metadata);
    assert_every_package_declared_once(&manifest, &names);
}

#[test]
fn every_production_edge_is_declared_allowed_or_temporary() {
    let (manifest, metadata) = load();
    let (edges, _) = collect_edges(&metadata);
    assert_edges_declared(&manifest, &edges);
}

#[test]
fn every_temporary_edge_names_a_removal_phase() {
    let manifest = load_manifest();
    assert_temporary_edges_have_removal_phases(&manifest);
}

#[test]
fn production_graph_has_no_cycles() {
    let (manifest, metadata) = load();
    let (edges, _) = collect_edges(&metadata);
    assert_no_production_cycles(&manifest, &edges);
}

#[test]
fn production_never_depends_on_non_production() {
    let (manifest, metadata) = load();
    let (edges, _) = collect_edges(&metadata);
    assert_no_production_to_non_production_edges(&manifest, &edges);
}

#[test]
fn planned_crates_satisfy_declared_edges_once_present() {
    // Same check as `every_production_edge_is_declared_allowed_or_temporary`
    // but covers planned entries too: `assert_edges_declared` already walks
    // every present package against the manifest, planned or not. This test
    // documents the contract: the moment jyth-runtime (or any planned crate)
    // exists, its declared edge list is enforced, which rejects any
    // runtime-to-concrete-adapter dependency.
    let (manifest, metadata) = load();
    let (edges, _) = collect_edges(&metadata);
    assert_edges_declared(&manifest, &edges);
}

/// A deliberately introduced forbidden edge must make the architecture test
/// fail (WP1 exit criterion). This test drives the checker directly against
/// an in-memory manifest so the negative path is deterministic and does not
/// depend on live metadata.
#[test]
#[should_panic(expected = "undeclared production edge")]
fn deliberately_introduced_forbidden_edge_fails() {
    let manifest = load_manifest();
    // The canonical forbidden edge from the plan: a runtime-to-concrete-
    // adapter dependency. jyth-runtime is declared (planned) with a closed
    // contract-only list, so the moment this edge appears it must fail.
    let edges = vec![Edge {
        from: "jyth-runtime".to_owned(),
        to: "hypervisor-hcs".to_owned(),
        kind: "normal".to_owned(),
    }];
    assert_edges_declared(&manifest, &edges);
}
