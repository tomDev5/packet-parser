use std::{fmt::Display, net::IpAddr};

use pnet::packet::ip::IpNextHeaderProtocol;

use crate::packet::{HeaderPosition, Packet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}

impl Display for FourTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.source_ip, self.source_port, self.destination_ip, self.destination_port
        )
    }
}

impl<'a> Packet<'a> {
    pub fn get_four_tuple(&self, position: HeaderPosition) -> Option<FourTuple> {
        let l3 = self.get_l3(position)?;
        let l4 = self.get_l4(position)?;

        Some(FourTuple {
            source_ip: l3.get_source()?,
            source_port: l4.get_source()?,
            destination_ip: l3.get_destination()?,
            destination_port: l4.get_destination()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: IpNextHeaderProtocol,
}

impl Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -{}-> {}:{}",
            self.source_ip,
            self.source_port,
            self.protocol,
            self.destination_ip,
            self.destination_port
        )
    }
}

impl<'a> Packet<'a> {
    pub fn get_five_tuple(&self, position: HeaderPosition) -> Option<FiveTuple> {
        let l3 = self.get_l3(position)?;
        let l4 = self.get_l4(position)?;

        Some(FiveTuple {
            source_ip: l3.get_source()?,
            source_port: l4.get_source()?,
            destination_ip: l3.get_destination()?,
            destination_port: l4.get_destination()?,
            protocol: l3.get_l4_protocol()?,
        })
    }
}
