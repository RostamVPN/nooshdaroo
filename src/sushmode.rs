//! SushMode fallback transport — stub for v1.0, native implementation planned for v1.1.
//!
//! SushMode uses Noise_NK encryption over UDP micro-frames on port 53.
//! The full protocol requires:
//!   1. Noise_NK_25519_ChaChaPoly_BLAKE2s handshake (snow crate)
//!   2. Micro-frame encoding (length-prefixed encrypted frames)
//!   3. Local SOCKS5 server relaying connections through the tunnel
//!
//! This is substantially more complex than spawning the Go dnstt-client binary,
//! so v1.0 ships with DNSTT support only. SushMode will be added in v1.1.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Run SushMode tunnel with a local SOCKS5 proxy.
///
/// Currently a stub — prints a message and exits.
/// In v1.1 this will:
/// 1. Connect to a SushMode server (Noise_NK handshake)
/// 2. Start a local SOCKS5 server on `listen_addr`
/// 3. Relay SOCKS5 connections through the encrypted tunnel
pub fn run(listen_addr: &str, servers: &[String], _running: &Arc<AtomicBool>) {
    eprintln!("[!] SushMode native support coming in v1.1.");
    eprintln!();
    eprintln!("    SushMode servers available ({}):", servers.len());
    for (i, s) in servers.iter().take(3).enumerate() {
        eprintln!("      {}. {}:53", i + 1, s);
    }
    if servers.len() > 3 {
        eprintln!("      ... and {} more", servers.len() - 3);
    }
    eprintln!();
    eprintln!("    For now, use DNSTT (the default). Place dnstt-client next to this binary.");
    eprintln!("    Intended listen address was: {}", listen_addr);
    eprintln!();
    eprintln!("    Download dnstt-client from:");
    eprintln!("      https://www.bamsoftware.com/software/dnstt/");
}
