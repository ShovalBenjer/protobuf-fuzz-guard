//! `jev`: cost/latency-aware model router.
//!
//! Picks the cheapest model route that can plausibly handle a task:
//! local small LMs (Ollama) first, then free tiers, paid escalation last.
//! Dependency-free: std only, so it never touches the dependency tree
//! and stays green on MSRV.

pub mod router;

pub use router::{Route, default_routes, estimate_complexity, route};
