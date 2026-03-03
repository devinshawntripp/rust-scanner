mod batch;
mod enrich;
mod mapping;

// --- Public re-exports (same API as the original flat file) ---
pub use batch::osv_batch_query;
pub use enrich::osv_enrich_findings;
pub use mapping::map_osv_results_to_findings;

// --- Internal re-exports for test access (used by vuln/tests.rs) ---
#[cfg(test)]
pub(in crate::vuln) use enrich::drop_fixed_findings;

// --- Internal re-exports for sibling submodule access ---
