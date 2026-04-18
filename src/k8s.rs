use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::Command;

use crate::utils::progress;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct K8sWorkload {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub containers: Vec<K8sContainer>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct K8sContainer {
    pub name: String,
    pub image: String,
    pub image_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterScanReport {
    pub cluster_context: String,
    pub namespaces_scanned: Vec<String>,
    pub workloads: Vec<K8sWorkload>,
    pub unique_images: Vec<String>,
    pub image_reports: Vec<ImageScanResult>,
    pub summary: ClusterSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageScanResult {
    pub image: String,
    pub workloads: Vec<String>,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub scan_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub total_workloads: usize,
    pub total_images: usize,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub images_with_critical: Vec<String>,
}

/// Discover workloads in the cluster using kubectl
pub fn discover_workloads(
    kubeconfig: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
) -> Result<Vec<K8sWorkload>, String> {
    let mut cmd = Command::new("kubectl");
    cmd.arg("get");
    cmd.arg("pods");

    if let Some(kc) = kubeconfig {
        cmd.arg("--kubeconfig").arg(kc);
    }
    if let Some(ctx) = context {
        cmd.arg("--context").arg(ctx);
    }
    if let Some(ns) = namespace {
        cmd.arg("-n").arg(ns);
    } else {
        cmd.arg("--all-namespaces");
    }

    cmd.arg("-o").arg("json");

    let output = cmd
        .output()
        .map_err(|e| format!("kubectl not found or failed: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("kubectl failed: {}", stderr));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse kubectl output: {}", e))?;

    let mut workloads: Vec<K8sWorkload> = Vec::new();

    if let Some(items) = json["items"].as_array() {
        for item in items {
            let ns = item["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();

            // Get the owning controller kind
            let kind = if let Some(owners) = item["metadata"]["ownerReferences"].as_array() {
                owners
                    .first()
                    .and_then(|o| o["kind"].as_str())
                    .unwrap_or("Pod")
                    .to_string()
            } else {
                "Pod".to_string()
            };

            let owner_name = if let Some(owners) = item["metadata"]["ownerReferences"].as_array() {
                owners
                    .first()
                    .and_then(|o| o["name"].as_str())
                    .unwrap_or(&name)
                    .to_string()
            } else {
                name.clone()
            };

            let mut containers = Vec::new();

            // Regular containers
            if let Some(specs) = item["spec"]["containers"].as_array() {
                for c in specs {
                    containers.push(K8sContainer {
                        name: c["name"].as_str().unwrap_or("unknown").to_string(),
                        image: c["image"].as_str().unwrap_or("unknown").to_string(),
                        image_id: item["status"]["containerStatuses"]
                            .as_array()
                            .and_then(|statuses| {
                                statuses
                                    .iter()
                                    .find(|s| s["name"] == c["name"])
                                    .and_then(|s| s["imageID"].as_str().map(|s| s.to_string()))
                            }),
                    });
                }
            }

            // Init containers
            if let Some(specs) = item["spec"]["initContainers"].as_array() {
                for c in specs {
                    containers.push(K8sContainer {
                        name: format!("init:{}", c["name"].as_str().unwrap_or("unknown")),
                        image: c["image"].as_str().unwrap_or("unknown").to_string(),
                        image_id: None,
                    });
                }
            }

            workloads.push(K8sWorkload {
                namespace: ns,
                kind,
                name: owner_name,
                containers,
            });
        }
    }

    // Deduplicate by owner (multiple pod replicas -> one workload)
    dedupe_workloads(&mut workloads);

    Ok(workloads)
}

fn dedupe_workloads(workloads: &mut Vec<K8sWorkload>) {
    let mut seen: HashSet<String> = HashSet::new();
    workloads.retain(|w| {
        let key = format!("{}/{}/{}", w.namespace, w.kind, w.name);
        seen.insert(key)
    });
}

/// Extract unique images from workloads
pub fn unique_images(workloads: &[K8sWorkload]) -> Vec<String> {
    let mut images: HashSet<String> = HashSet::new();
    for w in workloads {
        for c in &w.containers {
            if c.image != "unknown" {
                images.insert(c.image.clone());
            }
        }
    }
    let mut sorted: Vec<String> = images.into_iter().collect();
    sorted.sort();
    sorted
}

/// Pull and save a Docker image to a tar file using docker or crane as fallback
pub fn pull_and_save_image(image: &str, dest: &str) -> Result<(), String> {
    progress("k8s.image.pull", &format!("Pulling {}", image));

    let pull = Command::new("docker")
        .args(["pull", image])
        .output()
        .map_err(|e| format!("docker pull failed: {}", e))?;

    if !pull.status.success() {
        // Try with crane as fallback
        let crane = Command::new("crane").args(["pull", image, dest]).output();

        if let Ok(o) = crane {
            if o.status.success() {
                return Ok(());
            }
        }

        return Err(format!(
            "Failed to pull {}: {}",
            image,
            String::from_utf8_lossy(&pull.stderr)
        ));
    }

    let save = Command::new("docker")
        .args(["save", image, "-o", dest])
        .output()
        .map_err(|e| format!("docker save failed: {}", e))?;

    if !save.status.success() {
        return Err(format!(
            "Failed to save {}: {}",
            image,
            String::from_utf8_lossy(&save.stderr)
        ));
    }

    Ok(())
}
