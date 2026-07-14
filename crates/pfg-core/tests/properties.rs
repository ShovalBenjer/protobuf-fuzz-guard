//! Property-based robustness tests (migration plan, Phase 1).
//!
//! The scanner is a security tool: `parse_proto`, `scan`, and `generate_all`
//! must never panic, whatever the input. These properties complement the
//! `fuzz/` crate by running on stable in every CI test job.

use pfg_core::{generate_all, parse_proto, scan};
use proptest::prelude::*;

proptest! {
    /// The full pipeline never panics on arbitrary (possibly non-proto) text.
    #[test]
    fn pipeline_never_panics_on_arbitrary_text(input in ".{0,2048}") {
        let proto = parse_proto(&input, "prop.proto");
        let _ = scan(&proto);
        let _ = generate_all(&proto, None);
    }

    /// Every recorded span lies within the source and message names are
    /// exact slices of it.
    #[test]
    fn spans_are_in_bounds(input in ".{0,2048}") {
        let proto = parse_proto(&input, "prop.proto");
        for msg in proto.all_messages() {
            prop_assert!(msg.span.end <= input.len());
            prop_assert!(msg.span.start <= msg.span.end);
            prop_assert_eq!(&input[msg.span.start..msg.span.end], msg.name.as_str());
            for f in &msg.fields {
                prop_assert!(f.span.end <= input.len());
                prop_assert!(f.span.start <= f.span.end);
            }
        }
    }

    /// Structured well-formed messages always parse back with the same
    /// name, field name, and field number.
    #[test]
    fn well_formed_message_roundtrips(
        msg_name in "[A-Z][a-zA-Z0-9]{0,12}",
        field_name in "[a-z][a-z0-9_]{0,12}",
        number in 1i64..100_000,
        repeated in any::<bool>(),
    ) {
        let label = if repeated { "repeated " } else { "" };
        let src = format!("message {msg_name} {{\n    {label}string {field_name} = {number};\n}}\n");
        let proto = parse_proto(&src, "gen.proto");
        prop_assert_eq!(proto.messages.len(), 1);
        prop_assert_eq!(proto.messages[0].name.as_str(), msg_name.as_str());
        let f = &proto.messages[0].fields[0];
        prop_assert_eq!(f.name.as_str(), field_name.as_str());
        prop_assert_eq!(f.number, number);
        prop_assert_eq!(f.repeated, repeated);
    }

    /// Scanning is deterministic: same input, same findings.
    #[test]
    fn scan_is_deterministic(input in ".{0,1024}") {
        let a = scan(&parse_proto(&input, "a.proto"));
        let b = scan(&parse_proto(&input, "a.proto"));
        prop_assert_eq!(a, b);
    }
}
