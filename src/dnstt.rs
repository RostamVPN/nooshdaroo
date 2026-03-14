//! DNSTT child process management — launches and monitors the Go dnstt-client binary.
//!
//! The Go binary provides a SOCKS5 server. This module:
//! 1. Finds the dnstt-client binary on disk or PATH
//! 2. Spawns it with the correct arguments
//! 3. Monitors health (restart on crash, rotate domains)
//! 4. Cleans up on Ctrl+C

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::ui;

/// Parameters for launching dnstt-client
pub struct DnsttParams {
    pub binary: String,
    pub listen: String,
    pub domains: Vec<(String, String)>,
    pub resolver: String,
    pub quiet: bool,
}

#[cfg(target_os = "windows")]
const BINARY_NAME: &str = "dnstt-client.exe";
#[cfg(not(target_os = "windows"))]
const BINARY_NAME: &str = "dnstt-client";

/// Find the dnstt-client binary.
///
/// Search order:
/// 1. Explicit path (--dnstt-client argument)
/// 2. Same directory as this executable
/// 3. Current working directory
/// 4. System PATH
pub fn find_binary(explicit_path: Option<&str>) -> Option<String> {
    if let Some(path) = explicit_path {
        if Path::new(path).exists() {
            log::debug!("Using explicit dnstt-client path: {}", path);
            return Some(path.to_string());
        }
        log::warn!("Specified dnstt-client path does not exist: {}", path);
        return None;
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let candidate = exe_dir.join(BINARY_NAME);
            if candidate.exists() {
                log::debug!("Found dnstt-client next to exe: {}", candidate.display());
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    let cwd_candidate = PathBuf::from(BINARY_NAME);
    if cwd_candidate.exists() {
        return Some(BINARY_NAME.to_string());
    }

    #[cfg(target_os = "windows")]
    let which = "where";
    #[cfg(not(target_os = "windows"))]
    let which = "which";

    if let Ok(output) = Command::new(which).arg(BINARY_NAME).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }

    None
}

/// Spawn the dnstt-client process.
fn spawn_dnstt(
    binary: &str,
    listen: &str,
    domain: &str,
    pubkey: &str,
    resolver: &str,
) -> std::io::Result<Child> {
    let resolver_addr = if resolver.contains(':') {
        resolver.to_string()
    } else {
        format!("{}:53", resolver)
    };

    log::info!(
        "Spawning: {} -udp {} -domain {} -pubkey {}... -listen {}",
        binary,
        resolver_addr,
        domain,
        &pubkey[..12.min(pubkey.len())],
        listen
    );

    Command::new(binary)
        .arg("-udp")
        .arg(&resolver_addr)
        .arg("-domain")
        .arg(domain)
        .arg("-pubkey")
        .arg(pubkey)
        .arg("-listen")
        .arg(listen)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

/// Kill a child process cleanly.
fn kill_child(child: &mut Child) {
    log::debug!("Killing dnstt-client (pid={})", child.id());

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGTERM);
        }
        std::thread::sleep(Duration::from_millis(200));
        let _ = child.kill();
    }

    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }

    let _ = child.wait();
}

/// Main run loop: spawn dnstt-client, monitor, rotate domains on failure.
pub fn run(params: &DnsttParams, running: &Arc<AtomicBool>, cfg: &Config) {
    let mut domain_idx = 0;
    let mut consecutive_failures = 0u32;
    let max_consecutive = 3u32;

    while running.load(Ordering::SeqCst) {
        if domain_idx >= params.domains.len() {
            if consecutive_failures > 0 {
                ui::print_error(&format!(
                    "All {} domains exhausted.",
                    params.domains.len()
                ));

                let servers = cfg.sushmode_servers();
                if !servers.is_empty() {
                    ui::print_status("Fallback", "Trying SushMode...");
                    crate::sushmode::run(&params.listen, &servers, running);
                    return;
                }

                ui::print_dim("Retrying DNSTT from the start in 5s...");
            }
            domain_idx = 0;
            consecutive_failures = 0;

            if !sleep_interruptible(Duration::from_secs(5), running) {
                break;
            }
        }

        let (ref domain, ref pubkey) = params.domains[domain_idx];

        if !params.quiet {
            ui::print_connecting(domain, &params.resolver);
        }

        let mut child = match spawn_dnstt(
            &params.binary,
            &params.listen,
            domain,
            pubkey,
            &params.resolver,
        ) {
            Ok(c) => c,
            Err(e) => {
                ui::print_error(&format!("Failed to spawn dnstt-client: {}", e));
                domain_idx += 1;
                consecutive_failures += 1;
                if !sleep_interruptible(Duration::from_secs(2), running) {
                    break;
                }
                continue;
            }
        };

        // Wait for startup
        std::thread::sleep(Duration::from_millis(500));

        // Check if it immediately crashed
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(ref mut stderr) = child.stderr {
                    use std::io::Read;
                    let mut buf = vec![0u8; 4096];
                    if let Ok(n) = stderr.read(&mut buf) {
                        if n > 0 {
                            let msg = String::from_utf8_lossy(&buf[..n]);
                            log::debug!("dnstt-client stderr: {}", msg.trim());
                        }
                    }
                }
                ui::print_error(&format!(
                    "dnstt-client exited (code {}), rotating domain...",
                    status
                ));
                domain_idx += 1;
                consecutive_failures += 1;
                if !sleep_interruptible(Duration::from_secs(1), running) {
                    break;
                }
                continue;
            }
            Ok(None) => {
                // Running successfully
                consecutive_failures = 0;
            }
            Err(e) => {
                log::warn!("Failed to check child: {}", e);
            }
        }

        // Connected!
        if !params.quiet {
            ui::print_ready(&params.listen);
        }

        // Monitor loop
        let started = Instant::now();
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(2));

            match child.try_wait() {
                Ok(Some(status)) => {
                    let uptime = started.elapsed();

                    if uptime < Duration::from_secs(10) {
                        domain_idx += 1;
                        consecutive_failures += 1;
                        ui::print_reconnecting(
                            &format!("exited after {}s, code {}", uptime.as_secs(), status),
                            params.domains.get(domain_idx).map(|(d, _)| d.as_str()).unwrap_or("?"),
                        );
                    } else {
                        if consecutive_failures >= max_consecutive {
                            domain_idx += 1;
                            consecutive_failures = 0;
                        } else {
                            consecutive_failures += 1;
                        }
                        ui::print_reconnecting(
                            &format!("ran for {}s, code {}", uptime.as_secs(), status),
                            domain,
                        );
                    }

                    if !sleep_interruptible(Duration::from_secs(2), running) {
                        return;
                    }
                    break;
                }
                Ok(None) => continue,
                Err(e) => {
                    log::warn!("Error checking child: {}", e);
                    continue;
                }
            }
        }

        // Shutting down
        if !running.load(Ordering::SeqCst) {
            ui::print_shutdown();
            kill_child(&mut child);
            return;
        }
    }
}

/// Sleep that can be interrupted by Ctrl+C.
fn sleep_interruptible(duration: Duration, running: &Arc<AtomicBool>) -> bool {
    let start = Instant::now();
    while start.elapsed() < duration {
        if !running.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    true
}
