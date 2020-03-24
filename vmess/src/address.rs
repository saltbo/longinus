

use oh_my_rust::*;

#[derive(Debug, Clone)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(Box<[u8]>)
}

impl std::fmt::Display for Addr {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::V4(x) => std::fmt::Display::fmt(&std::net::Ipv4Addr::from(*x), fmt),
            Addr::V6(x) => std::fmt::Display::fmt(&std::net::Ipv6Addr::from(*x), fmt),
            Addr::Domain(x) => std::fmt::Display::fmt(std::str::from_utf8(x).msg(std::fmt::Error)?, fmt)
        }
    }
}