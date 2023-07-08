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
        let (l3, l4) = match position {
            HeaderPosition::Inner | HeaderPosition::Outer => {
                (self.get_l3(position)?, self.get_l4(position)?)
            }
            HeaderPosition::Innermost => self
                .get_l3(HeaderPosition::Inner)
                .and_then(|l3| self.get_l4(HeaderPosition::Inner).map(|l4| (l3, l4)))
                .or_else(|| {
                    self.get_l3(HeaderPosition::Outer)
                        .and_then(|l3| self.get_l4(HeaderPosition::Outer).map(|l4| (l3, l4)))
                })?,
        };

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
        let (l3, l4) = match position {
            HeaderPosition::Inner | HeaderPosition::Outer => {
                (self.get_l3(position)?, self.get_l4(position)?)
            }
            HeaderPosition::Innermost => self
                .get_l3(HeaderPosition::Inner)
                .and_then(|l3| self.get_l4(HeaderPosition::Inner).map(|l4| (l3, l4)))
                .or_else(|| {
                    self.get_l3(HeaderPosition::Outer)
                        .and_then(|l3| self.get_l4(HeaderPosition::Outer).map(|l4| (l3, l4)))
                })?,
        };

        Some(FiveTuple {
            source_ip: l3.get_source()?,
            source_port: l4.get_source()?,
            destination_ip: l3.get_destination()?,
            destination_port: l4.get_destination()?,
            protocol: l3.get_l4_protocol()?,
        })
    }
}

impl From<FiveTuple> for FourTuple {
    fn from(five_tuple: FiveTuple) -> Self {
        Self {
            source_ip: five_tuple.source_ip,
            source_port: five_tuple.source_port,
            destination_ip: five_tuple.destination_ip,
            destination_port: five_tuple.destination_port,
        }
    }
}
