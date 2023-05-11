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
    pub packet: ExtensionPacket<'a>,
    protocol: Ipv6ExtensionProtocolIds,
}

#[derive(Debug, PartialEq)]
pub struct Ipv6Extensions<'a> {
    pub extensions: SmallVec<[Ipv6Extension<'a>; 2]>,
    pub next_protocol: IpNextHeaderProtocol,
    pub length: usize,
}

impl Ipv6Extensions<'_> {
    fn new(next_protocol: IpNextHeaderProtocol) -> Self {
        Self {
            extensions: Default::default(),
            next_protocol,
            length: Default::default(),
        }
    }
}

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

impl<'a> TryFrom<(&'a [u8], IpNextHeaderProtocol)> for Ipv6Extensions<'a> {
    type Error = ParseError;

    fn try_from(
        (mut buf, mut next_protocol): (&'a [u8], IpNextHeaderProtocol),
    ) -> Result<Self, Self::Error> {
        let mut extensions = Ipv6Extensions::new(next_protocol);
        loop {
            let extension: Result<Ipv6Extension, ParseError> = (next_protocol, buf).try_into();
            match extension {
                Ok(extension) => {
                    let extension_length = extension.packet.get_hdr_ext_len() as usize * 8 + 8;
                    buf = &buf[extension_length..];
                    next_protocol = extension.packet.get_next_header();
                    extensions.extensions.push(extension);
                    extensions.length += extension_length;
                }
                Err(ParseError::ExtensionParseFailure) => Err(ParseError::ExtensionParseFailure)?,
                Err(ParseError::UnknownIpv6Extension) => break,
            }
        }

        extensions.next_protocol = next_protocol;
        Ok(extensions)
    }
}
