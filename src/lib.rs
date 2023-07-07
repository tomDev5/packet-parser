//! Fast, Zero-Copy, packet parser
//!
//! # Introduction
//! This library is using [`pnet`] for the packet parsing, so adding more protocols is stupidly easy.
//! <br>
//! It puts more emphasys on all parsing being zero-copy, and all tests are checked for zero allocations
//! <br>
//! It currently supports the following protocols:
//! - `Ethernet`
//! - `IPv4 (+options)`, `IPv6 (+extension)`, `Arp`
//! - `TCP`, `UDP`, `ICMP`, `ICMPv6`
//! - `GRE tunnel`
//!
//! # Parsing packets
//! Simple parsing of a packet from bytes:
//! ```rust
//! use packet_parser::packet::{Packet, ParseError};
//!
//! fn main() -> Result<(), ParseError> {
//!     let packet = &[
//!         0x78u8, 0x2b, 0x46, 0x4b, 0x3b, 0xab, 0xb4, 0x8c, 0x9d, 0x5d, 0x81, 0x8b, 0x08, 0x00,
//!         0x45, 0x00, 0x00, 0x32, 0x36, 0x2b, 0x40, 0x00, 0x80, 0x06, 0x08, 0x94, 0xc0, 0xa8,
//!         0x1d, 0x11, 0xc0, 0xa8, 0x1d, 0xa5, 0xec, 0x62, 0x63, 0xdd, 0xc6, 0xef, 0xa3, 0xdf,
//!         0x88, 0xce, 0x7e, 0xbc, 0x50, 0x18, 0x02, 0x01, 0x0e, 0x83, 0x00, 0x00, 0x08, 0xff,
//!         0x08, 0x00, 0x07, 0x9e, 0x08, 0x00, 0x00, 0x00,
//!     ];
//!     let parsed = Packet::try_from(packet.as_slice())?;
//!     println!("{parsed:#?}");
//!     Ok(())
//! }
//! ```
//! This code will output the following:
//! ```text
//! Regular(
//!     Ethernet(
//!         EthernetPacket { destination : 78:2b:46:4b:3b:ab, source : b4:8c:9d:5d:81:8b, ethertype : EtherType(2048),  },
//!         [],
//!         Ipv4(
//!             Ipv4Packet { version : 4, header_length : 5, dscp : 0, ecn : 0, total_length : 50, identification : 13867, flags : 2, fragment_offset : 0, ttl : 128, next_level_protocol : IpNextHeaderProtocol(6), checksum : 2196, source : 192.168.29.17, destination : 192.168.29.165, options : [],  },
//!             Tcp(
//!                 TcpPacket { source : 60514, destination : 25565, sequence : 3337593823, acknowledgement : 2295234236, data_offset : 5, reserved : 0, flags : 24, window : 513, checksum : 3715, urgent_ptr : 0, options : [],  },
//!             ),
//!         ),
//!     ),
//! )
//! ```

/// Layer 2 protocols
pub mod l2;
/// Layer 3 protocols
pub mod l3;
/// L3 extensions - zero copy options & extensions
///
/// Pnet allows parsing ipv4 options and ipv6 extension.
/// Unfortunatly, parsing them involves Vec, which allcoates memory.
/// These extensions allow zero copy parsing.
pub mod l3_extensions;
/// Layer 4 protocols
pub mod l4;
pub mod l4_extensions;
/// General packet structures (four tuple, encapsulations, etc)
pub mod packet;
pub mod tuples;
