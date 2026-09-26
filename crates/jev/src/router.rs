//! jev router: cost/latency-aware model routing.
//!
//! Priority: local small LMs (Ollama) -> free tiers -> paid escalation only when needed.
//!
//! Std-only by design: the liveness probe is a TCP connect, so this module
//! adds no dependencies to the tree.

use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// One candidate model route.
#[derive(Debug, Clone)]
pub struct Route {
    /// Short identifier, e.g. `"ollama-local"`.
    pub name: &'static str,
    /// Route kind: `"ollama"`, `"github-models"`, `"free-api"`, or `"paid"`.
    pub kind: &'static str,
    /// Model identifier passed to the provider.
    pub model: String,
    /// Base URL of the provider API.
    pub base_url: &'static str,
    /// Env var holding the API key, when the route needs one.
    pub api_key_env: Option<&'static str>,
    /// USD cost per 1k tokens (informational).
    pub cost_per_1k: f64,
    /// Typical latency in milliseconds (informational).
    pub latency_ms_p50: u64,
    /// Provider max context window (informational).
    pub max_context: u64,
    /// Whether the route is reachable right now.
    pub available: bool,
}

/// Candidate routes, cheapest first.
#[must_use]
pub fn default_routes() -> Vec<Route> {
    vec![
        Route {
            name: "ollama-local",
            kind: "ollama",
            model: env::var("JEV_LOCAL_MODEL").unwrap_or_else(|_| "qwen2.5:7b".into()),
            base_url: "http://localhost:11434",
            api_key_env: None,
            cost_per_1k: 0.0,
            latency_ms_p50: 400,
            max_context: 32768,
            available: false,
        },
        Route {
            name: "github-models",
            kind: "github-models",
            model: env::var("JEV_GH_MODEL").unwrap_or_else(|_| "gpt-4o-mini".into()),
            base_url: "https://models.github.ai/inference",
            api_key_env: Some("JEV_MODEL_TOKEN"),
            cost_per_1k: 0.0,
            latency_ms_p50: 1200,
            max_context: 128_000,
            available: false,
        },
    ]
}

/// Std-only liveness probe: TCP connect to the URL's host:port.
/// No HTTP request is needed; an open port means the daemon is up.
fn ollama_alive(base_url: &str) -> bool {
    let host_port = base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let addr = host_port
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next());
    addr.is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_millis(1500)).is_ok())
}

/// Heuristic task complexity in `[0.0, 1.0]`: length plus domain keywords.
#[allow(clippy::cast_precision_loss)] // length is capped at 4000; float precision is irrelevant here
#[must_use]
pub fn estimate_complexity(task: &str) -> f64 {
    let t = task.to_lowercase();
    let mut score = 0.4 * (task.len().min(4000) as f64 / 4000.0);
    for marker in [
        "prove",
        "security",
        "architecture",
        "refactor",
        "distributed",
        "concurrency",
    ] {
        if t.contains(marker) {
            score += 0.15;
        }
    }
    score.min(1.0)
}

/// Pick the cheapest route that can plausibly handle the task.
///
/// `budget` is `"free"`, `"balanced"`, or `"max-quality"`.
/// Returns an error when no route is reachable.
pub fn route(task: &str, budget: &str) -> Result<Route, &'static str> {
    let complexity = estimate_complexity(task);
    let mut routes = default_routes();
    routes[0].available = ollama_alive(routes[0].base_url);
    routes[1].available = routes[1]
        .api_key_env
        .is_some_and(|key| env::var(key).is_ok());

    let local = routes[0].clone();
    let hosted = routes[1].clone();
    if local.available && (complexity < 0.55 || budget == "free") {
        return Ok(local);
    }
    if hosted.available {
        return Ok(hosted);
    }
    if local.available {
        return Ok(local);
    }
    Err("no model route available: start Ollama or set JEV_MODEL_TOKEN")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_cheapest_first() {
        let routes = default_routes();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].name, "ollama-local");
        assert_eq!(routes[1].api_key_env, Some("JEV_MODEL_TOKEN"));
    }

    #[test]
    fn complexity_grows_with_size_and_keywords() {
        let small = estimate_complexity("fix typo");
        let big =
            estimate_complexity("prove the security architecture of this distributed refactor");
        assert!(small < big);
    }

    #[test]
    fn complexity_is_bounded() {
        for task in [
            "",
            "hi",
            "prove security architecture refactor distributed concurrency",
        ] {
            let c = estimate_complexity(task);
            assert!((0.0..=1.0).contains(&c), "out of bounds: {c}");
        }
    }

    #[test]
    fn router_is_honest_when_nothing_is_up() {
        // `route` must not panic when no route is reachable; it reports an error.
        // (In environments with Ollama or JEV_MODEL_TOKEN set it succeeds instead;
        // either outcome is valid here.)
        let _ = route("hello", "balanced");
    }
}
