//! Lightweight SOCKS5 server — reserved for future SushMode integration.
//!
//! When SushMode is implemented natively, this module will provide the local
//! SOCKS5 listener that accepts browser connections and relays them through
//! the SushMode encrypted tunnel.
//!
//! The Go dnstt-client binary has its own built-in SOCKS5 server, so this
//! module is NOT used for the DNSTT path.

#![allow(dead_code)]

use std::net::SocketAddr;

/// SOCKS5 protocol version
const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods
const AUTH_NO_AUTH: u8 = 0x00;

/// SOCKS5 commands
const CMD_CONNECT: u8 = 0x01;

/// SOCKS5 address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes
const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// A parsed SOCKS5 CONNECT request
pub struct Socks5Request {
    /// Target address (IP or domain)
    pub addr: Socks5Addr,
    /// Target port
    pub port: u16,
}

/// SOCKS5 target address
pub enum Socks5Addr {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Domain(String),
}

impl Socks5Addr {
    pub fn to_socket_addr(&self, port: u16) -> Option<SocketAddr> {
        match self {
            Socks5Addr::Ipv4(ip) => {
                Some(SocketAddr::new((*ip).into(), port))
            }
            Socks5Addr::Ipv6(ip) => {
                Some(SocketAddr::new((*ip).into(), port))
            }
            Socks5Addr::Domain(_) => None, // Needs DNS resolution
        }
    }
}

impl std::fmt::Display for Socks5Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Addr::Ipv4(ip) => {
                write!(f, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
            }
            Socks5Addr::Ipv6(ip) => {
                let addr: std::net::Ipv6Addr = (*ip).into();
                write!(f, "{}", addr)
            }
            Socks5Addr::Domain(d) => write!(f, "{}", d),
        }
    }
}
