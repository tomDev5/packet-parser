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

#[derive(Debug)]
pub enum L2Packet<'a> {
    Ethernet {
        header: EthernetPacket<'a>,
        vlans: VlanPackets<'a>,
        l3: L3Packet<'a>,
    },
}
const ETHERNET_LENGTH: usize = 14;
const VLAN_LENGTH: usize = 4;

impl<'a> TryFrom<&'a [u8]> for L2Packet<'a> {
    type Error = ParseError;

    fn try_from(mut bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let header = EthernetPacket::new(bytes).ok_or(ParseError::Ethernet)?;
        bytes = &bytes[ETHERNET_LENGTH..];

        let mut vlans = VlanPackets::new();
        let mut ethertype = header.get_ethertype();
        while ethertype == EtherTypes::Vlan {
            let vlan_packet = VlanPacket::new(bytes).ok_or(ParseError::Vlan)?;
            bytes = &bytes[VLAN_LENGTH..];
            ethertype = vlan_packet.get_ethertype();
            vlans.push(vlan_packet);
        }
        let l3 = (ethertype, bytes).try_into()?;

        Ok(Self::Ethernet { header, vlans, l3 })
    }
}

impl<'a> L2Packet<'a> {
    pub fn get_l3(&self) -> Option<&L3Packet> {
        match self {
            L2Packet::Ethernet {
                header: _,
                vlans: _,
                l3,
            } => Some(l3),
        }
    }

    pub fn get_vlans(&self) -> &'a VlanPackets {
        match self {
            L2Packet::Ethernet {
                header: _,
                vlans,
                l3: _,
            } => vlans,
        }
    }

    pub fn get_vlan_at(&self, index: usize) -> Option<&VlanPacket> {
        match self {
            L2Packet::Ethernet {
                header: _,
                vlans: vlan,
                l3: _,
            } => vlan.get(index),
        }
    }
}
