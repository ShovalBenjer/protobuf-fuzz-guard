//! `jev`: cost/latency-aware model router.
//!
//! Picks the cheapest model route that can plausibly handle a task:
//! local small LMs (Ollama) first, then free tiers, paid escalation last.
//! Dependency-free: std only, so it never touches the dependency tree
//! and stays green on MSRV.
//!
//! ADR-0009 hardening, enforced in code:
//! - [`router::decide`] appends every routing decision (kept-local reason +
//!   confidence) to an append-only `jev/decisions.jsonl` log — the audit
//!   trail for the escalation threshold and the flywheel training data.
//! - [`router::UNCERTAINTY_BAND`]: complexity estimates near the
//!   local/escalate boundary escalate to the frontier route. Uncertain cases
//!   never stay local by default.
//! - [`schema::validate_local_output`]: local (SLM) structured outputs are
//!   schema-checked by deterministic code before use — length-capped, must be
//!   one JSON object, required fields present.
//! - **The router routes; it never judges or gates.** There is no
//!   allow/deny verdict type here, no content-based gating, and
//!   [`router::route`] only ever reports infrastructure unavailability.
//!   Per ADR-0009, no SLM judges a decision — and neither does the router.

pub mod router;
pub mod schema;

pub use router::{
    DECISIONS_PATH_ENV, DEFAULT_DECISIONS_PATH, Decision, LOCAL_BOUNDARY, Reason, Route,
    UNCERTAINTY_BAND, confidence, decide, default_routes, estimate_complexity, pick, route,
};
pub use schema::{MAX_LOCAL_OUTPUT_LEN, SchemaError, validate_local_output};
