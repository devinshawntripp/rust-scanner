//! Pipeline stage manifest and progress tracking for scan orchestration.
//!
//! Defines ordered scan stages with weight percentages for each scan type.
//! The pipeline emits a manifest event at scan start and stage-transition
//! events throughout the scan, providing accurate percentages for the worker
//! and UI to display.

use std::sync::Mutex;
use std::sync::OnceLock;

use crate::utils::{progress, progress_pct};

/// A single stage in the scan pipeline.
#[derive(Debug, Clone)]
pub struct PipelineStage {
    pub id: &'static str,
    pub label: &'static str,
    pub weight: u8,
}

/// Active pipeline state, tracks cumulative progress.
#[derive(Debug)]
struct PipelineState {
    stages: Vec<PipelineStage>,
    current_idx: usize,
    base_pct: u8,
}

static PIPELINE: OnceLock<Mutex<Option<PipelineState>>> = OnceLock::new();

fn pipeline_lock() -> &'static Mutex<Option<PipelineState>> {
    PIPELINE.get_or_init(|| Mutex::new(None))
}

/// Container scan pipeline stages and weights (sum = 100).
pub fn container_pipeline() -> Vec<PipelineStage> {
    vec![
        PipelineStage { id: "extract", label: "Extract", weight: 10 },
        PipelineStage { id: "inventory", label: "Package Inventory", weight: 10 },
        PipelineStage { id: "osv_query", label: "OSV Query", weight: 10 },
        PipelineStage { id: "osv_enrich", label: "OSV Enrichment", weight: 15 },
        PipelineStage { id: "nvd_enrich", label: "NVD Enrichment", weight: 20 },
        PipelineStage { id: "redhat", label: "Red Hat OVAL", weight: 10 },
        PipelineStage { id: "distro_feeds", label: "Distro Feeds", weight: 5 },
        PipelineStage { id: "epss", label: "EPSS Scoring", weight: 5 },
        PipelineStage { id: "kev", label: "KEV Catalog", weight: 5 },
        PipelineStage { id: "report", label: "Report Assembly", weight: 10 },
    ]
}

/// Binary scan pipeline stages and weights (sum = 100).
pub fn binary_pipeline() -> Vec<PipelineStage> {
    vec![
        PipelineStage { id: "parse", label: "Binary Parse", weight: 10 },
        PipelineStage { id: "nvd_lookup", label: "NVD Lookup", weight: 30 },
        PipelineStage { id: "go_osv", label: "Go Module OSV", weight: 10 },
        PipelineStage { id: "nvd_enrich", label: "NVD Enrichment", weight: 20 },
        PipelineStage { id: "epss", label: "EPSS Scoring", weight: 10 },
        PipelineStage { id: "kev", label: "KEV Catalog", weight: 10 },
        PipelineStage { id: "report", label: "Report Assembly", weight: 10 },
    ]
}

/// ISO scan pipeline stages and weights (sum = 100).
pub fn iso_pipeline() -> Vec<PipelineStage> {
    vec![
        PipelineStage { id: "detect", label: "ISO Detection", weight: 5 },
        PipelineStage { id: "inventory", label: "Package Inventory", weight: 15 },
        PipelineStage { id: "osv_query", label: "OSV Query", weight: 10 },
        PipelineStage { id: "osv_enrich", label: "OSV Enrichment", weight: 15 },
        PipelineStage { id: "nvd_enrich", label: "NVD Enrichment", weight: 20 },
        PipelineStage { id: "redhat", label: "Red Hat OVAL", weight: 10 },
        PipelineStage { id: "epss", label: "EPSS Scoring", weight: 5 },
        PipelineStage { id: "kev", label: "KEV Catalog", weight: 5 },
        PipelineStage { id: "report", label: "Report Assembly", weight: 15 },
    ]
}

/// Source tarball scan pipeline stages and weights (sum = 100).
pub fn source_pipeline() -> Vec<PipelineStage> {
    vec![
        PipelineStage { id: "extract", label: "Extract", weight: 10 },
        PipelineStage { id: "inventory", label: "Package Inventory", weight: 15 },
        PipelineStage { id: "nvd_lookup", label: "NVD Lookup", weight: 30 },
        PipelineStage { id: "nvd_enrich", label: "NVD Enrichment", weight: 15 },
        PipelineStage { id: "epss", label: "EPSS Scoring", weight: 10 },
        PipelineStage { id: "kev", label: "KEV Catalog", weight: 10 },
        PipelineStage { id: "report", label: "Report Assembly", weight: 10 },
    ]
}

/// Initialize the pipeline for a scan type and emit the manifest event.
pub fn init_pipeline(scan_type: &str) {
    let stages = match scan_type {
        "container" => container_pipeline(),
        "binary" => binary_pipeline(),
        "iso" => iso_pipeline(),
        "source" => source_pipeline(),
        _ => container_pipeline(),
    };

    emit_pipeline_manifest(&stages);

    if let Ok(mut guard) = pipeline_lock().lock() {
        *guard = Some(PipelineState {
            stages,
            current_idx: 0,
            base_pct: 0,
        });
    }
}

/// Emit the scan.pipeline manifest event listing all stages with weights.
fn emit_pipeline_manifest(stages: &[PipelineStage]) {
    let pipeline_json: Vec<serde_json::Value> = stages
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "label": s.label,
                "weight": s.weight,
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "ts": chrono::Local::now().to_rfc3339(),
        "level": "info",
        "component": "scan",
        "event": "scan.pipeline",
        "stage": "scan.pipeline",
        "detail": "",
        "pct": 0,
        "pipeline": pipeline_json,
    });
    // Write the manifest directly to the progress file and stderr
    let json_line = format!("{}\n", manifest);
    crate::utils::write_progress_raw(&json_line);
}

/// Signal the start of a pipeline stage. Emits a pipeline.stage.start event
/// with the cumulative percentage at this stage's beginning.
pub fn enter_stage(stage_id: &str) {
    let pct = if let Ok(mut guard) = pipeline_lock().lock() {
        if let Some(ref mut state) = *guard {
            // Find the stage index
            if let Some(idx) = state.stages.iter().position(|s| s.id == stage_id) {
                // Calculate cumulative pct up to this stage
                let cumulative: u8 = state.stages[..idx]
                    .iter()
                    .map(|s| s.weight)
                    .sum();
                state.current_idx = idx;
                state.base_pct = cumulative;
                cumulative
            } else {
                state.base_pct
            }
        } else {
            0
        }
    } else {
        0
    };

    progress_pct(
        "pipeline.stage.start",
        stage_id,
        pct,
    );
}

/// Report sub-stage progress within the current stage.
/// `fraction` is 0.0..=1.0 representing progress within the current stage.
pub fn stage_progress(detail: &str, fraction: f32) {
    let pct = if let Ok(guard) = pipeline_lock().lock() {
        if let Some(ref state) = *guard {
            let stage_weight = state.stages
                .get(state.current_idx)
                .map(|s| s.weight)
                .unwrap_or(0);
            let within = (fraction.clamp(0.0, 1.0) * stage_weight as f32) as u8;
            (state.base_pct + within).min(100)
        } else {
            0
        }
    } else {
        0
    };

    progress_pct("pipeline.stage.progress", detail, pct);
}

/// Mark the scan pipeline as complete (100%).
pub fn finish_pipeline() {
    progress_pct("pipeline.complete", "", 100);
    if let Ok(mut guard) = pipeline_lock().lock() {
        *guard = None;
    }
}

/// Get the current overall percentage (for progress bar rendering).
pub fn current_pct() -> u8 {
    if let Ok(guard) = pipeline_lock().lock() {
        if let Some(ref state) = *guard {
            return state.base_pct;
        }
    }
    0
}
