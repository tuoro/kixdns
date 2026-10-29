#[cfg(test)]
mod client_address_tests;
pub mod concurrency;
#[cfg(test)]
mod cookie_tests;
pub mod core;
#[cfg(test)]
mod domain_exact_tests;
#[cfg(test)]
mod ecs_scope_tests;
#[cfg(test)]
mod edns_reply_tests;
pub mod execution;
mod geo;
#[cfg(test)]
mod geo_reload_tests;
#[cfg(test)]
mod inflight_wait_tests;
pub mod matcher_adapter;
#[cfg(test)]
mod name_text_tests;
pub(crate) mod observation;
pub mod phases;
pub mod pipeline;
#[cfg(test)]
mod private_address_tests;
#[cfg(test)]
mod query_flags_tests;
#[cfg(test)]
mod question_case_tests;
pub mod refresh;
#[cfg(test)]
mod refresh_class_tests;
pub mod response;
pub(crate) mod response_log;
#[cfg(test)]
mod rule_index_tests;
pub mod rules;
#[cfg(test)]
mod tcp_pool_tests;
#[cfg(test)]
mod test_support;
pub mod transport;
pub mod types;
pub mod upstream;
#[cfg(test)]
mod upstream_reply_tests;
pub mod utils;

pub use concurrency::PermitManager;
pub use core::{Engine, EngineBuilder};
pub use execution::PreParsedData;
pub use matcher_adapter::*;
pub use pipeline::select_pipeline;
pub use types::{EngineInner, FastPathResponse};

pub use response::{extract_ttl, extract_ttl_for_refresh};
pub(crate) use response::{make_static_cname_answer, make_static_ip_answer};
pub use rules::Decision;
pub use utils::engine_helpers;
