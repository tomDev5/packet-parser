use crate::{
    l2::{self, L2Packet},
    l3::{self, L3Packet},
    l4::L4Packet,
};
use pnet::packet::{ethernet::EtherType, Packet as _};
use std::fmt::Display;

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Invalid protocol after tunnel")]
    InvalidProtocolAfterTunnel,
    #[error("Error in L2")]
    L2Error(#[from] l2::ParseError),
    #[error("Error in L3")]
    L3Error(#[from] l3::ParseError),
    #[error("Missing L3")]
    MissingL3,
    #[error("Missing L4")]
    MissingL4,
    #[error("GRE Routing not supported in pnet")]
    GreRoutingNotSupportedInPnet,
}

#[derive(Debug, PartialEq)]
#[repr(align(64))]
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

        Ok(match l4 {
            L4Packet::Gre(gre) => {
                if gre.get_routing_present() == 1 {
                    return Err(ParseError::GreRoutingNotSupportedInPnet);
                }
                let outer_length = bytes.len() - gre.payload().len();
                let inner_buffer = bytes
                    .get(outer_length..)
                    .ok_or(ParseError::InvalidProtocolAfterTunnel)?;
                let after_tunnel = (EtherType(gre.get_protocol_type()), inner_buffer).try_into()?;

                Packet::L3Tunnel(l2, after_tunnel)
            }
            _ => Packet::Regular(l2),
        })
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum HeaderPosition {
    Inner,
    Outer,
    Innermost,
}

impl<'a> Packet<'a> {
    pub fn get_l2(&self, position: HeaderPosition) -> Option<&L2Packet<'a>> {
        match (position, self) {
            (HeaderPosition::Inner, _) => None, // no l2 encaps are supported atm
            (HeaderPosition::Outer, Packet::Regular(l2)) => l2.into(),
            (HeaderPosition::Outer, Packet::L3Tunnel(l2, _)) => l2.into(),
            (HeaderPosition::Innermost, Packet::Regular(l2)) => l2.into(),
            (HeaderPosition::Innermost, Packet::L3Tunnel(l2, _)) => l2.into(), // will change if we support l2 encaps
        }
    }

    pub fn get_l3(&self, position: HeaderPosition) -> Option<&L3Packet<'a>> {
        match (position, self) {
            (HeaderPosition::Inner, Packet::Regular(_)) => None,
            (HeaderPosition::Inner, Packet::L3Tunnel(_, inner_l3)) => inner_l3.into(),
            (HeaderPosition::Outer, Packet::Regular(l2)) => l2.get_l3(),
            (HeaderPosition::Outer, Packet::L3Tunnel(l2, _)) => l2.get_l3(),
            (HeaderPosition::Innermost, Packet::Regular(l2)) => l2.get_l3(),
            (HeaderPosition::Innermost, Packet::L3Tunnel(_, inner_l3)) => inner_l3.into(),
        }
    }

    pub fn get_l4(&self, position: HeaderPosition) -> Option<&L4Packet<'a>> {
        // this is correct unless we have an L4Tunnel someday
        self.get_l3(position)?.get_l4()
    }

    pub fn get_payload(&self) -> Option<&[u8]> {
        self.get_l4(HeaderPosition::Innermost)
            .and_then(move |l4| match l4 {
                L4Packet::Tcp(tcp) => Some(tcp.payload()),
                L4Packet::Udp(udp) => Some(udp.payload()),
                L4Packet::Gre(gre) => Some(gre.payload()),
                L4Packet::Icmp(icmp) => Some(icmp.payload()),
                L4Packet::Icmpv6(icmpv6) => Some(icmpv6.payload()),
            })
    }
}

impl Display for Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Packet::Regular(inner) => write!(f, "Packet: {}", inner),
            Packet::L3Tunnel(outer, inner) => {
                write!(f, "Encapsulated Packet: {} | {}", outer, inner)
            }
        }
    }
}
