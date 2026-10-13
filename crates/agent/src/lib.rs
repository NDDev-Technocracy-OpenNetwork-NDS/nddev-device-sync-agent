//! Compiled-in native module composition. Domain contracts come from NDS core;
//! concrete tools retain their own data, permissions and execution policies.
pub mod view;

/// Bound shared by artifact packaging and native worker admission.
pub const GDS_WORKER_MAX_BYTES: u64 = 128 * 1024 * 1024;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod native;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use native::NativeAgent;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod worker;
