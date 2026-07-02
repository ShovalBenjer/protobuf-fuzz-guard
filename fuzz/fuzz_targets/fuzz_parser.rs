//! Self-dogfooding fuzz target (research §5): the scanner must never panic on
//! hostile `.proto` text. We fuzz the full pipeline — parse → scan → generate —
//! against arbitrary input.
//!
//! Run (nightly required):
//!   cargo +nightly fuzz run fuzz_parser
//! Minimize a crash:
//!   cargo +nightly fuzz tmin fuzz_parser <artifact>

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let proto = pfg_core::parse_proto(text, "fuzz.proto");
        // None of these may panic, regardless of input.
        let _findings = pfg_core::scan(&proto);
        let _harnesses = pfg_core::generate_all(&proto, None);
    }
});
