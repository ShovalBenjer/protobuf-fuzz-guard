//! Finding schema: deterministic validation, dedup, and corpus manifest tests.
//!
//! Wires `pfg_core::findings` into the existing scanner: the scanner's own
//! output must satisfy the schema it feeds, and the seed corpus manifest must
//! match the seeds on disk.

use std::path::PathBuf;

use pfg_core::{SCHEMA_VERSION, dedup_findings, parse_proto, scan, validate_findings};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn schema_version_is_documented() {
    let schema = std::fs::read_to_string(crate_dir().join("../../docs/findings.schema.json"))
        .expect("docs/findings.schema.json exists");
    assert!(
        schema.contains(&format!("\"const\":{SCHEMA_VERSION}")),
        "schema doc pins the current SCHEMA_VERSION"
    );
}

#[test]
fn scanner_output_validates_and_dedups_cleanly() {
    // Every seed scans to findings that satisfy the schema; scanning the
    // whole corpus twice and deduping must not lose or duplicate anything.
    let seeds = crate_dir().join("../../fuzz/seeds");
    let mut all = Vec::new();
    for seed in [
        "simple.proto",
        "recursive.proto",
        "group_and_map.proto",
        "deep_nesting.proto",
    ] {
        let src = std::fs::read_to_string(seeds.join(seed)).expect("seed readable");
        let proto = parse_proto(&src, seed);
        all.extend(scan(&proto));
    }
    assert!(
        !all.is_empty(),
        "corpus must produce findings (otherwise the manifest's coverage notes lie)"
    );
    assert!(
        validate_findings(&all).is_empty(),
        "scanner output must satisfy the finding schema"
    );

    let doubled: Vec<_> = all.iter().cloned().chain(all.iter().cloned()).collect();
    let deduped = dedup_findings(doubled);
    assert_eq!(
        deduped.len(),
        all.len(),
        "dedup must collapse exact duplicates"
    );
    assert_eq!(
        deduped, all,
        "dedup is stable: first occurrence wins, order kept"
    );
}

#[test]
fn corpus_manifest_matches_seeds_on_disk() {
    let seeds_dir = crate_dir().join("../../fuzz/seeds");
    let manifest =
        std::fs::read_to_string(seeds_dir.join("manifest.json")).expect("corpus manifest exists");

    let mut on_disk: Vec<String> = std::fs::read_dir(&seeds_dir)
        .expect("seeds dir readable")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("proto"))
        })
        .collect();
    on_disk.sort();

    for seed in &on_disk {
        assert!(
            manifest.contains(&format!("\"{seed}\"")),
            "manifest must document seed {seed}"
        );
    }
    // Every "file" entry in the manifest must exist on disk (cheap textual
    // check: each quoted *.proto name in the manifest is a real file).
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("\"file\":") {
            let name = name.trim().trim_matches([',', '"', ' ']);
            assert!(
                seeds_dir.join(name).is_file(),
                "manifest references missing seed {name}"
            );
        }
    }
    assert!(!on_disk.is_empty());
}
