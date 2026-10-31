/// Public aliases keep the agent API names while core owns the query policy.
pub use nddev_device_sync_domain::{
    modules::{ModuleError as AgentError, ModuleObservation as ModuleState},
    state::Reachability,
};

pub use nddev_device_sync_browser_use::{
    Error as BrowserError, protocol::Document as BrowserDocument, view as browser,
};
pub use nddev_device_sync_cache_client::{Error as CacheError, view as cache};
pub use nddev_device_sync_cleaner::view as cleaner;
pub use nddev_device_sync_clipboard::view as clipboard;
pub use nddev_device_sync_github::view as github;
pub use nddev_device_sync_remote::view as remote;
pub use nddev_device_sync_sysinfo::view as sysinfo;
pub use nddev_device_sync_updater::view as updater;
