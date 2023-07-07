use pnet::packet::{
    gre::GrePacket,
    icmp::IcmpPacket,
    icmpv6::Icmpv6Packet,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    tcp::TcpPacket,
    udp::UdpPacket,
};
use std::fmt::Display;

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Failed to parse Tcp")]
    Tcp,
    #[error("Failed to parse Udp")]
    Udp,
    #[error("Failed to parse Gre")]
    Gre,
    #[error("Failed to parse Icmp")]
    Icmp,
    #[error("Failed to parse Icmpv6")]
    Icmpv6,
    #[error("Unknown L4 protocol")]
    UnknownL4Protocol,
}

#[derive(Debug, PartialEq)]
pub enum L4Packet<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Gre(GrePacket<'a>),
    Icmp(IcmpPacket<'a>),
    Icmpv6(Icmpv6Packet<'a>),
}

impl<'a> TryFrom<(IpNextHeaderProtocol, &'a [u8])> for L4Packet<'a> {
    type Error = ParseError;

    #[rustfmt::skip]
    fn try_from(
        (next_protocol, bytes): (IpNextHeaderProtocol, &'a [u8]),
    ) -> Result<Self, Self::Error> {
        Ok(match next_protocol {
            IpNextHeaderProtocols::Tcp => Self::Tcp(TcpPacket::new(bytes).ok_or(ParseError::Tcp)?),
            IpNextHeaderProtocols::Udp => Self::Udp(UdpPacket::new(bytes).ok_or(ParseError::Udp)?),
            IpNextHeaderProtocols::Gre => Self::Gre(GrePacket::new(bytes).ok_or(ParseError::Gre)?),
            IpNextHeaderProtocols::Icmp => Self::Icmp(IcmpPacket::new(bytes).ok_or(ParseError::Icmp)?),
            IpNextHeaderProtocols::Icmpv6 => Self::Icmpv6(Icmpv6Packet::new(bytes).ok_or(ParseError::Icmpv6)?),
            _ => Err(ParseError::UnknownL4Protocol)?,
        })
    }
}

impl<'a> L4Packet<'a> {
    pub fn get_source(&self) -> Option<u16> {
        match self {
            L4Packet::Tcp(header) => Some(header.get_source()),
            L4Packet::Udp(header) => Some(header.get_source()),
            L4Packet::Gre(_) | L4Packet::Icmp(_) | L4Packet::Icmpv6(_) => None,
        }
    }

    pub fn get_destination(&self) -> Option<u16> {
        match self {
            L4Packet::Tcp(header) => Some(header.get_destination()),
            L4Packet::Udp(header) => Some(header.get_destination()),
            L4Packet::Gre(_) | L4Packet::Icmp(_) | L4Packet::Icmpv6(_) => None,
        }
    }
}

impl Display for L4Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L4Packet::Tcp(_) => write!(f, "Tcp"),
            L4Packet::Udp(_) => write!(f, "Udp"),
            L4Packet::Gre(_) => write!(f, "Gre"),
            L4Packet::Icmp(_) => write!(f, "Icmp"),
            L4Packet::Icmpv6(_) => write!(f, "Icmpv6"),
        }
    }
}
