use crate::{
    l3_extensions::ipv6_extensions::{self, Ipv6Extensions},
    l4::{self, L4Packet},
};
use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherType, EtherTypes},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    Packet as _, PacketSize,
};
use std::{fmt::Display, net::IpAddr};

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Failed to parse IPv4")]
    IPv4,
    #[error("Failed to parse IPv6")]
    IPv6,
    #[error("Failed to parse Arp")]
    Arp,
    #[error("Error in L4")]
    L4Error(#[from] l4::ParseError),
    #[error("Error in IPv6 extentions")]
    Ipv6ExtensionError(#[from] ipv6_extensions::ParseError),
    #[error("Unknown L3 protocol")]
    UnknownL3Protocol,
}

#[derive(Debug, PartialEq)]
pub enum L3Packet<'a> {
    Ipv4(Ipv4Packet<'a>, L4Packet<'a>),
    Ipv6(Ipv6Packet<'a>, Ipv6Extensions<'a>, L4Packet<'a>),
    Arp(ArpPacket<'a>),
}

impl<'a> TryFrom<(EtherType, &'a [u8])> for L3Packet<'a> {
    type Error = ParseError;

    fn try_from((ether_type, bytes): (EtherType, &'a [u8])) -> Result<Self, Self::Error> {
        Ok(match ether_type {
            EtherTypes::Ipv4 => {
                let ip = Ipv4Packet::new(bytes).ok_or(ParseError::IPv4)?;
                let next_protocol = ip.get_next_level_protocol();
                let header_length = ip.packet_size() - ip.payload().len();
                let l4_packet = (next_protocol, &bytes[header_length..]).try_into()?;

                Self::Ipv4(ip, l4_packet)
            }
            EtherTypes::Ipv6 => {
                let ip = Ipv6Packet::new(bytes).ok_or(ParseError::IPv6)?;
                let header_length = ip.packet_size() - ip.payload().len();
                let extensions: Ipv6Extensions =
                    (&bytes[header_length..], ip.get_next_header()).try_into()?;
                let l4_packet: L4Packet = (
                    extensions.next_protocol,
                    &bytes[header_length + extensions.length..],
                )
                    .try_into()?;

                Self::Ipv6(ip, extensions, l4_packet)
            }
            EtherTypes::Arp => Self::Arp(ArpPacket::new(bytes).ok_or(ParseError::Arp)?),
            _ => Err(ParseError::UnknownL3Protocol)?,
        })
    }
}

impl<'a> L3Packet<'a> {
    pub fn get_source(&self) -> Option<IpAddr> {
        match self {
            L3Packet::Ipv4(header, _) => Some(header.get_source().into()),
            L3Packet::Ipv6(header, _, _) => Some(header.get_source().into()),
            _ => None,
        }
    }

    pub fn get_destination(&self) -> Option<IpAddr> {
        match self {
            L3Packet::Ipv4(header, _) => Some(header.get_destination().into()),
            L3Packet::Ipv6(header, _, _) => Some(header.get_destination().into()),
            _ => None,
        }
    }

    pub fn get_l4(&self) -> Option<&L4Packet<'a>> {
        match self {
            L3Packet::Ipv4(_, l4) => Some(l4),
            L3Packet::Ipv6(_, _, l4) => Some(l4),
            _ => None,
        }
    }
}

impl Display for L3Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L3Packet::Ipv4(_, l4) => write!(f, "IPv4, {}", l4),
            L3Packet::Ipv6(_, _, l4) => write!(f, "IPv6, {}", l4),
            L3Packet::Arp(_) => write!(f, "Arp"),
        }
    }
}
