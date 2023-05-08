use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv6::ExtensionPacket,
};
use smallvec::SmallVec;

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Failed to parse Ipv6 extension")]
    ExtensionParseFailure,
    #[error("Unknown IPv6 extension")]
    UnknownIpv6Extension,
}

#[repr(u8)]
#[derive(FromPrimitive, Debug, PartialEq, PartialOrd)]
enum Ipv6ExtensionProtocolIds {
    Hopopt = IpNextHeaderProtocols::Hopopt.0,
    Ipv6Route = IpNextHeaderProtocols::Ipv6Route.0,
    Ipv6Frag = IpNextHeaderProtocols::Ipv6Frag.0,
    Esp = IpNextHeaderProtocols::Esp.0,
    Ah = IpNextHeaderProtocols::Ah.0,
    Ipv6Opts = IpNextHeaderProtocols::Ipv6Opts.0,
    MobilityHeader = IpNextHeaderProtocols::MobilityHeader.0,
    Hip = IpNextHeaderProtocols::Hip.0,
    Shim6 = IpNextHeaderProtocols::Shim6.0,
    Test1 = IpNextHeaderProtocols::Test1.0,
    Test2 = IpNextHeaderProtocols::Test2.0,
}

#[derive(Debug, PartialEq)]
pub struct Ipv6Extension<'a> {
    packet: ExtensionPacket<'a>,
    protocol: Ipv6ExtensionProtocolIds,
}

pub type Ipv6Extensions<'a> = SmallVec<[Ipv6Extension<'a>; 2]>;

impl<'a> TryFrom<(IpNextHeaderProtocol, &'a [u8])> for Ipv6Extension<'a> {
    type Error = ParseError;

    #[rustfmt::skip]
    fn try_from(
        (next_protocol, bytes): (IpNextHeaderProtocol, &'a [u8]),
    ) -> Result<Self, Self::Error> {
        Ok(Ipv6Extension {
            packet: ExtensionPacket::new(bytes).ok_or(ParseError::ExtensionParseFailure)?,
            protocol: FromPrimitive::from_u8(next_protocol.0).ok_or(ParseError::UnknownIpv6Extension)?,
        })
    }
}
