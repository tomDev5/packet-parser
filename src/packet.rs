use std::net::IpAddr;

use pnet::packet::ethernet::{EtherType, EtherTypes};

use crate::{
    l2::{self, L2Packet},
    l3::{self, L3Packet},
    l4::L4Packet,
};

use pnet::packet::Packet as _;

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Invalid protocol after tunnel")]
    InvalidProtocolAfterTunnel,
    #[error("Error above")]
    L2Error(#[from] l2::ParseError),
    #[error("Error above")]
    L3Error(#[from] l3::ParseError),
    #[error("Missing L3")]
    MissingL3,
    #[error("Missing L4")]
    MissingL4,
}

#[derive(Debug)]
pub enum Packet<'a> {
    Regular(L2Packet<'a>),
    L3Tunnel(L2Packet<'a>, L3Packet<'a>),
}

impl<'a> TryFrom<&'a [u8]> for Packet<'a> {
    type Error = ParseError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let l2 = L2Packet::try_from(bytes)?;
        let l4 = l2
            .get_l3()
            .ok_or(ParseError::MissingL3)?
            .get_l4()
            .ok_or(ParseError::MissingL4)?;

        let L4Packet::Gre(gre) = l4 else {return Ok(Packet::Regular(l2)) };

        let outer_length = bytes.len() - gre.payload().len();

        let after_tunnel = match EtherType(gre.get_protocol_type()) {
            ethertype @ (EtherTypes::Ipv4 | EtherTypes::Ipv6) => {
                Some((ethertype, &bytes[outer_length..]).try_into()?)
            }
            _ => return Err(ParseError::InvalidProtocolAfterTunnel),
        };

        Ok(match after_tunnel {
            Some(after_tunnel) => Packet::L3Tunnel(l2, after_tunnel),
            None => Packet::Regular(l2),
        })
    }
}

impl<'a> Packet<'a> {
    pub fn get_inner_four_tuple(&self) -> Option<FourTuple> {
        let l3 = match self {
            Packet::Regular(inner) => inner.get_l3()?,
            Packet::L3Tunnel(_, l3) => l3,
        };

        let l4 = l3.get_l4()?;

        Some(FourTuple {
            source_ip: l3.get_source()?,
            source_port: l4.get_source()?,
            destination_ip: l3.get_destination()?,
            destination_port: l4.get_destination()?,
        })
    }

    pub fn get_inner_l3(&self) -> Option<&L3Packet> {
        match self {
            Packet::Regular(inner) => inner.get_l3(),
            Packet::L3Tunnel(_, l3) => Some(l3),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourTuple {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}
