use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::app::Runtime;

pub async fn run(runtime: Runtime) -> Result<()> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let roots: Vec<PathBuf> = runtime
        .config
        .paths
        .iter()
        .map(|root| root.path.clone())
        .collect();
    let mut watcher = build_watcher(event_tx)?;
    for root in &roots {
        watcher
            .watch(root, RecursiveMode::Recursive)
            .with_context(|| format!("watch {}", root.display()))?;
    }

    info!(roots = roots.len(), "daemon started");
    run_sync_cycle(&runtime, &roots_to_hashset(&roots)).await;

    let mut rescan_interval =
        tokio::time::interval(runtime.config.policy.rescan_interval_duration()?);
    let mut debounce = tokio::time::interval(Duration::from_secs(2));
    debounce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    rescan_interval.tick().await;
    debounce.tick().await;
    let mut dirty_roots = HashSet::new();
    let mut have_pending_events = false;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
                break;
            }
            _ = rescan_interval.tick() => {
                dirty_roots = roots_to_hashset(&roots);
                have_pending_events = true;
            }
            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(Ok(event)) => {
                        mark_dirty_roots(&roots, &event, &mut dirty_roots);
                        have_pending_events = true;
                    }
                    Some(Err(error)) => {
                        warn!(error = %error, "filesystem watcher returned an error");
                    }
                    None => break,
                }
            }
            _ = debounce.tick(), if have_pending_events => {
                if !dirty_roots.is_empty() {
                    run_sync_cycle(&runtime, &dirty_roots).await;
                }
                dirty_roots.clear();
                have_pending_events = false;
            }
        }
    }

    drop(watcher);
    Ok(())
}

fn build_watcher(
    event_tx: mpsc::UnboundedSender<notify::Result<Event>>,
) -> Result<RecommendedWatcher> {
    notify::recommended_watcher(move |result| {
        let _ = event_tx.send(result);
    })
    .context("create filesystem watcher")
}

async fn run_sync_cycle(runtime: &Runtime, dirty_roots: &HashSet<PathBuf>) {
    let selected: Vec<_> = runtime
        .config
        .paths
        .iter()
        .filter(|path| dirty_roots.contains(&path.path))
        .collect();

    if selected.is_empty() {
        return;
    }

    match runtime.sync_selected(&selected).await {
        Ok(summaries) => {
            for summary in summaries {
                info!(
                    root = %summary.root.display(),
                    files_scanned = summary.files_scanned,
                    changed_files = summary.changed_files,
                    deleted_files = summary.deleted_files,
                    uploaded_files = summary.uploaded_files,
                    reused_files = summary.reused_files,
                    bytes_uploaded = summary.bytes_uploaded,
                    errors = summary.errors,
                    "sync cycle complete"
                );
            }
        }
        Err(error) => {
            error!(error = %error, "sync cycle failed");
        }
    }
}

fn roots_to_hashset(roots: &[PathBuf]) -> HashSet<PathBuf> {
    roots.iter().cloned().collect()
}

fn mark_dirty_roots(roots: &[PathBuf], event: &Event, dirty_roots: &mut HashSet<PathBuf>) {
    for path in &event.paths {
        for root in roots {
            if path.starts_with(root) {
                dirty_roots.insert(root.clone());
            }
        }
    }
}
