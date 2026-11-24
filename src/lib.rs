pub mod cache;
pub mod cache_store;
pub mod config;
pub mod doh_server;
pub mod ecs;
pub mod ecs_scope;
pub mod engine;
pub mod listeners;
pub mod matcher;
pub mod observe;
// 面板只经控制通道读统计、跑诊断，控制通道是 Unix socket：别的系统上没有谁读它们，这三个模块不编进去 / The panel reads
// statistics and runs diagnostics over the control channel alone, a Unix socket: on other systems
// nothing reads them, and these three modules are not built
#[cfg(unix)]
pub mod panel;
#[cfg(unix)]
mod panel_querylog;
#[cfg(unix)]
pub mod panel_trace;
pub mod proto_utils;
pub mod socket_utils;
pub mod sparse_log;
pub mod watcher;
