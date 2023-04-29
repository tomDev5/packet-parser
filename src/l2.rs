use std::fmt::Display;

use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    vlan::VlanPacket,
};
use smallvec::SmallVec;
use thiserror::Error;

use crate::l3::{self, L3Packet};

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Failed to parse Ethernet")]
    Ethernet,
    #[error("Failed to parse Vlan")]
    Vlan,
    #[error("Error above")]
    ErrorAbove(#[from] l3::ParseError),
}

type VlanPackets<'a> = SmallVec<[VlanPacket<'a>; 2]>;

#[derive(Debug, PartialEq)]
pub enum L2Packet<'a> {
    Ethernet(EthernetPacket<'a>, VlanPackets<'a>, L3Packet<'a>),
}

impl<'a> TryFrom<&'a [u8]> for L2Packet<'a> {
    type Error = ParseError;

    fn try_from(mut bytes: &'a [u8]) -> Result<Self, Self::Error> {
        // this code is complex due to supporting any amount of vlans
        // (will not allocate memory unless more than 2 vlans)
        // may be vunrable, because technically it could receive a lot
        // of fucked up packets (100 vlans) and slow down
        // todo: consider adding a limit and maybe offer another function without one
        const ETHERNET_LENGTH_WITHOUT_PROTOCOL: usize = 14;
        const VLAN_LENGTH: usize = 4;

        let header = EthernetPacket::new(bytes).ok_or(ParseError::Ethernet)?;
        bytes = &bytes[ETHERNET_LENGTH_WITHOUT_PROTOCOL..];

        let mut vlans = VlanPackets::new();
        let mut ethertype = header.get_ethertype();
        while ethertype == EtherTypes::Vlan {
            let vlan_packet = VlanPacket::new(bytes).ok_or(ParseError::Vlan)?;
            bytes = &bytes[VLAN_LENGTH..];
            ethertype = vlan_packet.get_ethertype();
            vlans.push(vlan_packet);
        }
        let l3 = (ethertype, bytes).try_into()?;

        Ok(Self::Ethernet(header, vlans, l3))
    }
}

impl<'a> L2Packet<'a> {
    pub fn get_l3(&self) -> Option<&L3Packet<'a>> {
        match self {
            L2Packet::Ethernet(_, _, l3) => Some(l3),
        }
    }

    pub fn get_vlans(&self) -> &'a VlanPackets {
        match self {
            L2Packet::Ethernet(_, vlans, _) => vlans,
        }
    }

    pub fn get_vlan_at(&self, index: usize) -> Option<&VlanPacket> {
        match self {
            L2Packet::Ethernet(_, vlan, _) => vlan.get(index),
        }
    }
}

impl<'a> Display for L2Packet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L2Packet::Ethernet(_, vlans, l3) => {
                write!(f, "Ethernet, {} Vlans, {}", vlans.len(), l3)
            }
        }
    }
}
