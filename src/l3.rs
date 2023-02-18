use std::net::IpAddr;

use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherType, EtherTypes},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    PacketSize,
};

use pnet::packet::Packet as _;

use crate::l4::{self, L4Packet};

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Failed to parse IPv4")]
    IPv4,
    #[error("Failed to parse IPv6")]
    IPv6,
    #[error("Failed to parse Arp")]
    Arp,
    #[error("Error above")]
    ErrorAbove(#[from] l4::ParseError),
    #[error("Unknown protocol")]
    UnknownProtocol,
}

#[derive(Debug)]
pub enum L3Packet<'a> {
    Ipv4(Ipv4Packet<'a>, L4Packet<'a>),
    Ipv6(Ipv6Packet<'a>, L4Packet<'a>),
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
                let next_protocol = ip.get_next_header();
                let header_length = ip.packet_size() - ip.payload().len();
                let l4_packet = (next_protocol, &bytes[header_length..]).try_into()?;

                Self::Ipv6(ip, l4_packet)
            }
            EtherTypes::Arp => Self::Arp(ArpPacket::new(bytes).ok_or(ParseError::Arp)?),
            _ => return Err(ParseError::UnknownProtocol),
        })
    }
}

impl<'a> L3Packet<'a> {
    pub fn get_source(&self) -> Option<IpAddr> {
        match self {
            L3Packet::Ipv4(header, _) => Some(header.get_source().into()),
            L3Packet::Ipv6(header, _) => Some(header.get_source().into()),
            _ => None,
        }
    }

    pub fn get_destination(&self) -> Option<IpAddr> {
        match self {
            L3Packet::Ipv4(header, _) => Some(header.get_destination().into()),
            L3Packet::Ipv6(header, _) => Some(header.get_destination().into()),
            _ => None,
        }
    }

    pub fn get_l4(&self) -> Option<&L4Packet> {
        match self {
            L3Packet::Ipv4(_, l4) => Some(l4),
            L3Packet::Ipv6(_, l4) => Some(l4),
            _ => None,
        }
    }
}
